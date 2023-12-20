#!/usr/bin/env rake

require "rake/testtask"
require "rubocop/rake_task"

begin
  RuboCop::RakeTask.new(:lint) do |task|
    task.options += %w[--display-cop-names --no-color --parallel]
  end
rescue LoadError
  puts "rubocop is not available. Install the rubocop gem to run the lint tests."
end