# frozen_string_literal: true

require 'casbin-ruby/effect/effector'

module Casbin
  module Effect
    class AllowAndDenyEffector < Effect::Effector
      # returns a intermediate effect based on the matched effects of the enforcer
      def intermediate_effect(effects)
        return DENY if effects.include?(DENY)

        INDETERMINATE
      end

      # returns the final effect based on the matched effects of the enforcer
      def final_effect(effects)
        return DENY if effects.include?(DENY) || !effects.include?(ALLOW)

        ALLOW
      end
    end
  end
end
