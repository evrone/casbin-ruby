# frozen_string_literal: true

require 'keisan'

module Casbin
  module Util
    class Evaluator
      # evaluate an expression, using the operators, functions and names previously setup.
      def self.eval(expr, names = nil)
        Keisan::Calculator.new.evaluate expr, names
      end
    end
  end
end
