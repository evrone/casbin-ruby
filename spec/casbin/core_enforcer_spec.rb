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

    let(:model) { basic_config }
    let(:adapter) { basic_policy_file }

    context 'with existed rule' do
      let(:request) { %w[admin data1 read] }

      it { is_expected.to be_truthy }
    end

    context 'with non-existed rule' do
      let(:request) { %w[admin data1 write] }

      it { is_expected.to be_falsey }
    end
  end
end
