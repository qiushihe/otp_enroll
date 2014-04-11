#!/usr/bin/ruby

require_relative "lib/battle_net"

battle_net = BattleNet.new()
battle_net.enroll

puts "------------------------------------"
puts "Time offset: #{battle_net.time_offset}"
puts "Serial: #{battle_net.serial}"
puts "Secret Data: [#{battle_net.secret.join(", ")}]"
puts "Secret Code: #{battle_net.secret_code}"
puts "Restore Code: #{battle_net.restore_code}"
puts "URL: #{battle_net.provisioning_url}"
puts "------------------------------------"

totp = ROTP::TOTP.new(battle_net.secret_code, digits: 8)
while true do
  puts "Current Code: #{totp.now(true)}"
  sleep 30
end
