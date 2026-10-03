# Layout where Xray (VLESS+Reality) owns public tcp/443 and Caddy serves the website privately on 127.0.0.1:8444.
# Ordinary visitors reach Caddy transparently: Xray forwards every non-Reality connection to its "dest" (this Caddy).
{
	auto_https disable_redirects
	https_port 8444
}

# Plain HTTP stays public on :80 (also used for Let's Encrypt HTTP-01). Redirect to the real public HTTPS port.
http://@DOMAIN@ {
	redir https://@DOMAIN@{uri} permanent
}

@DOMAIN@:8444 {
	bind 127.0.0.1
	encode gzip
	reverse_proxy 127.0.0.1:3000
}
