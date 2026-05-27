// list of blocked IPs
// right now it is in-memory
// but it can be moved to a database or
// distributed cache like memcache or redis,etc.
package ip

type IPBlock map[string]bool

func NewIPBlock() IPBlock {
	return make(IPBlock)
}

func (b IPBlock) Add(ip string) {
	b[ip] = true
}

func (b IPBlock) IsBlocked(ip string) bool {
	return b[ip]
}

func (b IPBlock) Remove(ip string) {
	delete(b, ip)
}
