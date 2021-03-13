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
    shared_examples 'creates new enforcer' do
      it { expect(enforcer).not_to be_nil }
    end

    context 'when model is a string (path)' do
      let(:model) { basic_config }

      context 'when adapter is a string (path)' do
        let(:adapter) { basic_policy_file }

        it_behaves_like 'creates new enforcer'
      end

      context 'when adapter is a special object' do
        it_behaves_like 'creates new enforcer'
      end
    end

    context 'when model is a special object' do
      context 'when adapter is a string (path)' do
        let(:adapter) { basic_policy_file }

        it 'raises exception' do
          expect { enforcer }.to raise_error RuntimeError, 'Invalid parameters for enforcer.'
        end
      end

      context 'when adapter is a special object' do
        it_behaves_like 'creates new enforcer'
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

    context 'with RBAC' do
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

    context 'with RBAC with domains' do
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

    context 'with RBAC with resource roles' do
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

    context 'with ABAC' do
      let(:model) { abac_config }

      requests = {
        ['alice', { 'Owner' => 'alice' }, 'read'] => true,
        ['alice', { 'Owner' => 'alice' }, 'write'] => true,
        ['alice', { 'Owner' => 'diana' }, 'read'] => false,
        ['alice', { 'Owner' => 'diana' }, 'write'] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with ABAC with eval' do
      let(:model) { abac_with_eval_config }
      let(:adapter) { abac_with_eval_policy_file }

      requests = {
        [{ 'Age' => 12, 'Position' => { 'Rank' => 1 } }, '/data1', 'read'] => false,
        [{ 'Age' => 22, 'Position' => { 'Rank' => 1 } }, '/data1', 'read'] => true,
        [{ 'Age' => 22, 'Position' => { 'Rank' => 1 } }, '/data1', 'write'] => false,

        [{ 'Age' => 22, 'Position' => { 'Rank' => 1 } }, '/data2', 'read'] => false,
        [{ 'Age' => 22, 'Position' => { 'Rank' => 1 } }, '/data2', 'write'] => true,
        [{ 'Age' => 62, 'Position' => { 'Rank' => 1 } }, '/data2', 'read'] => false,

        [{ 'Age' => 22, 'Position' => { 'Rank' => 1 } }, '/data3', 'read'] => false,

        [{ 'Age' => 22, 'Position' => { 'Rank' => 1 } }, '/special_data', 'read'] => false,
        [{ 'Age' => 22, 'Position' => { 'Rank' => 2 } }, '/special_data', 'read'] => true
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with REST' do
      let(:model) { rest_config }
      let(:adapter) { rest_policy_file }

      requests = {
        %w[alice /alice_data/item GET] => true,
        %w[alice /alice_data/item POST] => false,
        %w[alice /alice_data/resource1 GET] => true,
        %w[alice /alice_data/resource1 POST] => true,
        %w[alice /cathy_data/item PUT] => false,

        %w[bob /alice_data/resource1 GET] => false,
        %w[bob /alice_data/resource2 GET] => true,
        %w[bob /alice_data/resource2 POST] => false,
        %w[bob /bob_data/resource DELETE] => false,
        %w[bob /bob_data/resource POST] => true,

        %w[cathy /cathy_data GET] => true,
        %w[cathy /cathy_data POST] => true,
        %w[cathy /cathy_data DELETE] => false,
        %w[cathy /cathy_data/resource GET] => false,
        %w[cathy /alice_data/resource1 GET] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with deny-override' do
      let(:model) { deny_override_config }
      let(:adapter) { deny_override_policy_file }

      requests = {
        %w[alice data1 read] => true,
        %w[alice data1 write] => true,
        %w[alice data2 read] => true,
        %w[alice data2 write] => false,
        %w[alice data3 read] => true,
        %w[alice data3 write] => true,

        %w[bob data1 read] => true,
        %w[bob data1 write] => true,
        %w[bob data2 read] => true,
        %w[bob data2 write] => true,
        %w[bob data3 read] => true,
        %w[bob data3 write] => true
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with allow-and-deny' do
      let(:model) { allow_and_deny_config }
      let(:adapter) { allow_and_deny_policy_file }

      requests = {
        %w[alice data1 read] => true,
        %w[alice data1 write] => false,
        %w[alice data2 read] => true,
        %w[alice data2 write] => false,
        %w[alice data3 read] => false,
        %w[alice data3 write] => false,

        %w[bob data1 read] => false,
        %w[bob data1 write] => false,
        %w[bob data2 read] => false,
        %w[bob data2 write] => true,
        %w[bob data3 read] => false,
        %w[bob data3 write] => false
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

    # It seems that this does not implemented in Python version. Examples was taken from here:
    # https://casbin.org/docs/en/priority-model#load-policy-with-priority-explicitly
    # Related PR in Golang version - https://github.com/casbin/casbin/pull/714/files
    # (we should add sorting by `p_priority`).
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
