#!/usr/bin/env ruby

require 'rubygems'

require 'json'
require 'openssl'
require 'sinatra'

get '/' do
  content_type 'text/plain; charset=us-ascii'

  "Hello from your friendly MSVA."
end

post '/reviewcert' do
  content_type "application/json"

  begin
    params = JSON.parse(request.body.string)
  rescue JSON::ParserError
    halt({ :valid => false, :message => "couldn't parse JSON query"})
  end

  unless (params["pkc"] && params["pkc"]["type"] == "x509der")
    halt({ :valid => false, :message => "pkc not present or of not-understood type" }.to_json)
  end

  data = params["pkc"]["data"].pack("C*")
  pkey = OpenSSL::X509::Certificate.new(data).public_key

  { :valid => false, :message => "Just testing!!" }.to_json
end

get '/noop' do
  { :available => true, :protoversion => 1, :server => "MSVA-Ruby 0.00001" }.to_json
end

post '/extracerts' do
  # TODO: fill in if we need to do so
  not_found
end
