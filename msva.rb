#!/usr/bin/env ruby

require 'rubygems'

require 'json'
require 'openssl'
require 'sinatra'

configure do
  git_dir = File.join(File.dirname(__FILE__), ".git")
  if File.directory?(git_dir)
    head = File.read("#{git_dir}/HEAD").strip.split[-1]
    @@git_rev = File.read(File.join(git_dir, head))
  end
end

get '/' do
  content_type "application/json"

  result = { :available => true, :protoversion => 1, :server => "MSVA-Ruby 0.00001" }
  result[:git_revision] = @@git_rev if @@git_rev
  result.to_json
end

post '/reviewcert' do
  content_type "application/json"

  begin
    params = JSON.parse(request.body.string)
  rescue JSON::ParserError
    halt({ :valid => false, :message => "couldn't parse JSON query"}.to_json)
  end

  unless (params["pkc"] && params["pkc"]["type"] == "x509der")
    halt({ :valid => false, :message => "pkc not present or of not-understood type" }.to_json)
  end

  data = params["pkc"]["data"].pack("C*")
  pkey = OpenSSL::X509::Certificate.new(data).public_key

  { :valid => false, :message => "Just testing!!" }.to_json
end

# TODO: fill in if we need to do so
# post '/extracerts' do
# end

not_found do
  content_type "application/json"

  { :status => 404, :message => "not found" }.to_json
end
