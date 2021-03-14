# frozen_string_literal: true

require 'casbin/core_enforcer'
require 'support/model_helper'

describe Casbin::CoreEnforcer do
  let(:model) { Casbin::Model::Model.new }
  let(:adapter) { Casbin::Persist::Adapter.new }
  let(:enforcer) { described_class.new model, adapter }
  let(:watcher) { double 'watcher' }

  describe '#initalize' do
    shared_examples 'creates new enforcer' do
      it { expect(enforcer).not_to be_nil }
    end

    context 'when model is a string (path)' do
      let(:model) { model_config 'basic' }

      context 'when adapter is a string (path)' do
        let(:adapter) { policy_file 'basic' }

        it_behaves_like 'creates new enforcer'
      end

      context 'when adapter is a special object' do
        it_behaves_like 'creates new enforcer'
      end
    end

    context 'when model is a special object' do
      context 'when adapter is a string (path)' do
        let(:adapter) { policy_file 'basic' }

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
      let(:model) { model_config 'basic' }
      let(:adapter) { policy_file 'basic' }

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
      let(:model) { model_config 'basic_with_root' }
      let(:adapter) { policy_file 'basic' }

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
      let(:model) { model_config 'basic_without_users' }
      let(:adapter) { policy_file 'basic_without_users' }

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
      let(:model) { model_config 'basic_without_resources' }
      let(:adapter) { policy_file 'basic_without_resources' }

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
      let(:model) { model_config 'rbac' }
      let(:adapter) { policy_file 'rbac' }

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
      let(:model) { model_config 'rbac_with_domains' }
      let(:adapter) { policy_file 'rbac_with_domains' }

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
      let(:model) { model_config 'rbac_with_resource_roles' }
      let(:adapter) { policy_file 'rbac_with_resource_roles' }

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

    context 'with RBAC with pattern' do
      let(:model) { model_config 'rbac_with_pattern' }
      let(:adapter) { policy_file 'rbac_with_pattern' }

      requests = {
        %w[/book/abc data1 GET] => true,
        %w[/book/1 data1 GET] => true,
        %w[/book/1 data1 POST] => false,
        %w[/other/1 data1 GET] => false
      }

      before do
        enforcer.role_manager.add_matching_func ->(key1, key2) { Casbin::Util::BuiltinOperators.key_match2 key1, key2 }
      end

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with ABAC' do
      let(:model) { model_config 'abac' }

      requests = {
        ['alice', { 'Owner' => 'alice' }, 'read'] => true,
        ['alice', { 'Owner' => 'alice' }, 'write'] => true,
        ['alice', { 'Owner' => 'diana' }, 'read'] => false,
        ['alice', { 'Owner' => 'diana' }, 'write'] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with ABAC with eval' do
      let(:model) { model_config 'abac_with_eval' }
      let(:adapter) { policy_file 'abac_with_eval' }

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
      let(:model) { model_config 'rest' }
      let(:adapter) { policy_file 'rest' }

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
      let(:model) { model_config 'deny_override' }
      let(:adapter) { policy_file 'deny_override' }

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
      let(:model) { model_config 'allow_and_deny' }
      let(:adapter) { policy_file 'allow_and_deny' }

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
      let(:model) { model_config 'priorities/implicit' }
      let(:adapter) { policy_file 'priorities/implicit' }

      requests = {
        %w[admin data1 read] => true,
        %w[admin data2 read] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    # It seems that this does not implemented in Python version. Examples was taken from here:
    # https://casbin.org/docs/en/priority-model#load-policy-with-priority-explicitly
    #
    # Related PR in Golang version - https://github.com/casbin/casbin/pull/714/files
    # (we should add sorting by `p_priority` after policy loading).
    xcontext 'with explicit priority' do
      let(:model) { model_config 'priorities/explicit' }
      let(:adapter) { policy_file 'priorities/explicit' }

      requests = {
        %w[alice data1 write] => true,
        %w[bob data2 read] => false,
        %w[bob data2 write] => true
      }

      it_behaves_like 'correctly enforces rules', requests
    end

    context 'with IP matching' do
      let(:model) { model_config 'ip' }
      let(:adapter) { policy_file 'ip' }

      requests = {
        %w[192.168.2.1 data1 read] => true,
        %w[192.168.2.101 data1 read] => true,
        %w[192.168.1.1 data1 read] => false,
        %w[192.168.2.101 data1 write] => false,
        %w[192.168.2.1 data2 read] => false,

        %w[10.0.2.3 data2 write] => true,
        %w[10.0.5.5 data2 write] => true,
        %w[10.0.5.5 data2 read] => false,
        %w[10.1.5.5 data2 write] => false,
        %w[10.0.5.5 data1 read] => false
      }

      it_behaves_like 'correctly enforces rules', requests
    end
  end
end
