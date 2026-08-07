// Package redis holds Redis-backed repositories (login challenges, auth codes, …).
//
// Shared connection: inject *redis.Client from internal/redis (DI RedisSet).
package redis
