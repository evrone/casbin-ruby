# frozen_string_literal: true

require 'casbin/core_enforcer'
require 'support/model_configs_context'
require 'support/policy_files_context'

describe Casbin::CoreEnforcer do
  include_context 'with model configs'
  include_context 'with policy files'

  let(:model) { Casbin::Model::Model.new }
  let(:adapter) { Casbin::Persist::Adapter.new }
  let(:enforcer) { described_class.new model, adapter }
  let(:watcher) { double 'watcher' }

  describe '#initalize' do
    context 'when model is a string (path)' do
      let(:model) { basic_config }

      context 'when adapter is a string (path)' do
        let(:adapter) { basic_policy_file }

        it 'creates new enforcer' do
          expect(enforcer).not_to be_nil
        end
      end
    end
  end

  describe '#enforce' do
    subject { enforcer.enforce(*request) }

    shared_examples 'correctly enforces rules' do |requests|
      requests.each do |request_data, result|
        context "with #{request_data.inspect}" do
          let(:request) { request_data }

          it { is_expected.to eq(result) }
        end
      end
    end

    context 'with basic' do
      let(:model) { basic_config }
      let(:adapter) { basic_policy_file }

      requests = {
        %w[admin data1 read] => true,
        %w[admin data2 write] => true,
        %w[admin data1 write] => false,
        %w[admin data2 read] => false,

        %w[admin2 data1 read] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with basic with root' do
      let(:model) { basic_with_root_config }
      let(:adapter) { basic_policy_file }

      requests = {
        %w[admin data1 read] => true,
        %w[admin data2 write] => true,
        %w[admin data1 write] => false,
        %w[admin data2 read] => false,

        %w[admin2 data1 read] => false,

        %w[root data1 read] => true,
        %w[root data1 write] => true,
        %w[root data2 read] => true,
        %w[root data2 write] => true
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with basic without users' do
      let(:model) { basic_without_users_config }
      let(:adapter) { basic_without_users_policy_file }

      requests = {
        %w[data1 read] => true,
        %w[data1 write] => false,
        %w[data2 read] => false,
        %w[data2 write] => true,
        %w[data3 read] => false,
        %w[data3 write] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with basic without resources' do
      let(:model) { basic_without_resources_config }
      let(:adapter) { basic_without_resources_policy_file }

      requests = {
        %w[alice read] => true,
        %w[alice write] => false,
        %w[bob read] => false,
        %w[bob write] => true,
        %w[charlie read] => false,
        %w[charlie write] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with rbac' do
      let(:model) { rbac_config }
      let(:adapter) { rbac_policy_file }

      requests = {
        %w[diana data1 read] => true,
        %w[diana data1 write] => false,
        %w[diana data2 read] => true,

        %w[alice data1 read] => false,

        %w[data_admin data2 read] => true,
        %w[data_admin data1 read] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with rbac with domains' do
      let(:model) { rbac_with_domains_config }
      let(:adapter) { rbac_with_domains_policy_file }

      requests = {
        %w[diana domain data1 read] => true,
        %w[diana third_domain data read] => false,
        %w[diana domain data2 read] => false,
        %w[diana domain data1 delete] => false,
        %w[diana other_domain data1 read] => true,
        %w[diana other_domain data1 write] => false,

        %w[alice domain data1 read] => false,
        %w[alice domain data2 read] => true,
        %w[alice domain data2 write] => false,
        %w[alice other_domain data1 read] => false,
        %w[alice other_domain data1 write] => false,

        %w[data_admin domain data1 read] => false,
        %w[data_admin other_domain data1 read] => true,
        %w[data_admin other_domain data1 write] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with rbac with resource roles' do
      let(:model) { rbac_with_resource_roles_config }
      let(:adapter) { rbac_with_resource_roles_policy_file }

      requests = {
        %w[alice data1 read] => true,
        %w[alice data1 write] => true,
        %w[alice data2 read] => false,
        %w[alice data2 write] => true,
        %w[alice data3 read] => false,
        %w[alice data3 write] => false,

        %w[bob data1 read] => false,
        %w[bob data1 write] => false,
        %w[bob data2 read] => false,
        %w[bob data2 write] => true,
        %w[bob data3 read] => false,
        %w[bob data3 write] => false,

        %w[data_group_admin data1 read] => false,
        %w[data_group_admin data1 write] => true,
        %w[data_group_admin data2 read] => false,
        %w[data_group_admin data2 write] => true,
        %w[data_group_admin data3 read] => false,
        %w[data_group_admin data3 write] => false,

        %w[diana data1 read] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with abac' do
      let(:model) { abac_config }

      requests = {
        ['alice', { 'Owner' => 'alice' }, 'read'] => true,
        ['alice', { 'Owner' => 'alice' }, 'write'] => true,
        ['alice', { 'Owner' => 'diana' }, 'read'] => false,
        ['alice', { 'Owner' => 'diana' }, 'write'] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with implicit priority' do
      let(:model) { implicit_priority_config }
      let(:adapter) { implicit_priority_policy_file }

      requests = {
        %w[admin data1 read] => true,
        %w[admin data2 read] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    # It seems that this does not work in Python. Examples was taken from here:
    # https://casbin.org/docs/en/priority-model#load-policy-with-priority-explicitly
    xcontext 'with explicit priority' do
      let(:model) { explicit_priority_config }
      let(:adapter) { explicit_priority_policy_file }

      requests = {
        %w[alice data1 write] => true,
        %w[bob data2 read] => false,
        %w[bob data2 write] => true
      }

      it_behaves_like 'correctly enforces rules', requests
    end
  end
end
