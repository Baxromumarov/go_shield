local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local refill = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local tokens = tonumber(redis.call("HGET", key, "tokens"))
local updated_at = tonumber(redis.call("HGET", key, "updated_at"))
local stored_capacity = tonumber(redis.call("HGET", key, "capacity"))
local stored_refill = tonumber(redis.call("HGET", key, "refill"))

if tokens == nil or updated_at == nil or stored_capacity ~= capacity or stored_refill ~= refill then
	tokens = capacity
	updated_at = now
else
	local elapsed = (now - updated_at) / 1000
	if elapsed > 0 and refill > 0 then
		tokens = math.min(capacity, tokens + (elapsed * refill))
		updated_at = now
	end
end

local allowed = 0
if tokens >= 1 then
	tokens = tokens - 1
	allowed = 1
end

redis.call("HSET", key, "tokens", tokens, "updated_at", updated_at, "capacity", capacity, "refill", refill)
redis.call("PEXPIRE", key, ttl)

return allowed