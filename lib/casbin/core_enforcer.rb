# frozen_string_literal: true

require 'casbin/effect/default_effector'
require 'casbin/effect/effector'
require 'casbin/model/function_map'
require 'casbin/model/model'
require 'casbin/persist/adapters/file_adapter'
require 'casbin/rbac/default_role_manager/role_manager'
require 'casbin/util'
require 'casbin/util/builtin_operators'
require 'casbin/util/simple_eval'

require 'logger'

module Casbin
  # CoreEnforcer defines the core functionality of an enforcer.
  # get_attr/set_attr methods is ported from Python as attr/attr=
  class CoreEnforcer
    def initialize(model = nil, adapter = nil)
      # we need some centralized logging management
      @logger = Logger.new($stdout)

      if model.is_a? String
        if adapter.is_a? String
          init_with_file(model, adapter)
        else
          init_with_adapter(model, adapter)
        end
      elsif adapter.is_a? String
        raise 'Invalid parameters for enforcer.'
      else
        init_with_model_and_adapter(model, adapter)
      end
    end

    attr_accessor :adapter, :auto_build_role_links, :auto_save, :effector, :enabled, :role_manager, :watcher
    attr_reader :model

    # initializes an enforcer with a model file and a policy file.
    def init_with_file(model_path, policy_path)
      a = Persist::Adapters::FileAdapter.new(policy_path)
      init_with_adapter(model_path, a)
    end

    # initializes an enforcer with a database adapter.
    def init_with_adapter(model_path, adapter = nil)
      m = new_model(model_path)
      init_with_model_and_adapter(m, adapter)

      self.model_path = model_path
    end

    # initializes an enforcer with a model and a database adapter.
    def init_with_model_and_adapter(m, adapter = nil)
      self.adapter = adapter

      self.model = m
      model.print_model

      init

      # Do not initialize the full policy when using a filtered adapter
      load_policy if adapter && !filtered?
    end

    # creates a model.
    def self.new_model(path = '', text = '')
      m = Model::Model.new
      if path.length.positive?
        m.load_model(path)
      else
        m.load_model_from_text(text)
      end

      m
    end

    def new_model(*args)
      self.class.new_model(*args)
    end

    # reloads the model from the model CONF file.
    # Because the policy is attached to a model, so the policy is invalidated and needs to be reloaded by calling
    # load_policy.
    def load_model
      self.model = new_model
      model.load_model model_path
      model.print_model
    end

    # sets the current model.
    def model=(m)
      @model = m
      self.fm = Model::FunctionMap.load_function_map
    end

    # clears all policy.
    def clear_policy
      model.clear_policy
    end

    # reloads the policy from file/database.
    def load_policy
      model.clear_policy
      adapter.load_policy model

      model.print_policy
      build_role_links if auto_build_role_links
    end

    # reloads a filtered policy from file/database.
    def load_filtered_policy(filter)
      model.clear_policy

      raise ArgumentError, 'filtered policies are not supported by this adapter' unless adapter.respond_to?(:filtered?)

      adapter.load_filtered_policy(model, filter)
      model.print_policy
      build_role_links if auto_build_role_links
    end

    # appends a filtered policy from file/database.
    def load_increment_filtered_policy(filter)
      raise ArgumentError, 'filtered policies are not supported by this adapter' unless adapter.respond_to?(:filtered?)

      adapter.load_filtered_policy(model, filter)
      model.print_policy
      build_role_links if auto_build_role_links
    end

    # returns true if the loaded policy has been filtered.
    def filtered?
      adapter.respond_to?(:filtered?) && adapter.filtered?
    end

    def save_policy
      raise 'cannot save a filtered policy' if filtered?

      adapter.save_policy(model)

      watcher&.update
    end

    alias enabled? enabled

    # manually rebuild the role inheritance relations.
    def build_role_links
      role_manager.clear
      model.build_role_links(role_manager)
    end

    # decides whether a "subject" can access a "object" with the operation "action",
    # input parameters are usually: (sub, obj, act).
    def enforce(*rvals)
      return false unless enabled?

      functions = fm.get_functions

      if model.model.key? 'g'
        model.model['g'].each do |key, ast|
          rm = ast.rm
          functions[key] = Util::BuiltinOperators.generate_g_function(rm)
        end
      end

      raise 'model is undefined' unless model.model['m']&.key?('m')

      r_tokens = model.model['r']['r'].tokens
      p_tokens = model.model['p']['p'].tokens

      raise 'invalid request size' if r_tokens.length != rvals.length

      exp_string = model.model['m']['m'].value

      has_eval = Util.has_eval(exp_string)
      expression = get_expression(exp_string, functions) unless has_eval

      policy_effects = Set.new
      matcher_results = Set.new

      r_parameters = {}
      r_tokens.each_with_index { |token, i| r_parameters[token] = rvals[i] }

      policy_len = model.model['p']['p'].policy.length

      if policy_len.positive?
        model.model['p']['p'].policy.each do |pvals|
          raise 'invalid policy size' if p_tokens.length != pvals.length

          p_parameters = {}
          p_tokens.each_with_index { |token, i| p_parameters[token] = pvals[i] }

          parameters = r_parameters.merge p_parameters

          if Util.has_eval(exp_string)
            rule_names = Util.get_eval_value(exp_string)
            rules = rule_names.map { |rule_name| Util.escape_assertion p_parameters[rule_name] }
            exp_with_rule = Util.replace_eval(exp_string, rules)
            expression = get_expression(exp_with_rule, functions)
          end

          result = expression.eval(parameters)

          case result
          when TrueClass, FalseClass
            unless result
              policy_effects.add(Effect::Effector::INDETERMINATE)
              next
            end
          when Numeric
            if result.zero?
              policy_effects.add(Effect::Effector::INDETERMINATE)
              next
            else
              matcher_results.add(result)
            end
          else
            raise 'matcher result should be true, false or a number'
          end

          if parameters.key? 'p_eft'
            case parameters['p_eft']
            when 'allow'
              policy_effects.add(Effect::Effector::ALLOW)
            when 'deny'
              policy_effects.add(Effect::Effector::DENY)
            else
              policy_effects.add(Effect::Effector::INDETERMINATE)
            end
          else
            policy_effects.add(Effect::Effector::ALLOW)
          end

          break if model.model['e']['e'].value == 'priority(p_eft) || deny'
        end
      else
        raise 'please make sure rule exists in policy when using eval() in matcher' if has_eval

        parameters = r_parameters.clone

        model.model['p']['p'].tokens.each { |token| parameters[token] = '' }

        result = expression.eval(parameters)

        policy_effects.add result ? Effect::Effector::ALLOW : Effect::Effector::INDETERMINATE
      end

      result = effector.merge_effects(model.model['e']['e'].value, policy_effects, matcher_results)

      # Log request.

      req_str = "Request: #{rvals.map(&:to_s).join ', '} ---> #{result}"

      if result
        logger.info(req_str)
      else
        # leaving this in error for now, if it's very noise this can be changed to info or debug
        logger.error(req_str)
      end

      result
    end

    protected

    attr_accessor :model_path, :fm, :auto_motify_watcher
    attr_reader :logger

    private

    attr_accessor :matcher_map

    def init
      self.role_manager = Rbac::DefaultRoleManager::RoleManager.new 10
      self.effector = Effect::DefaultEffector.new

      self.enabled = true
      self.auto_save = true
      self.auto_build_role_links = true
    end

    def self.get_expression(expr, functions = nil)
      Util::SimpleEval.new expr.gsub('&&', 'and').gsub('||', 'or').gsub('!', 'not'), functions
    end

    def get_expression(*args)
      self.class.get_expression(*args)
    end
  end
end
