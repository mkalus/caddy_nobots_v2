# NoBots v2

Caddy Server plugin to protect your website against web crawlers and bots. This is for Caddy v2 and is inspired by the
v1 Plugin https://github.com/caddy-plugins/nobots, originally by Jaume Martin.

## Requirements

* Go
* xcaddy: `go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`

## Usage

The directive for the Caddyfile is really simple. First, you have to place the bomb path next to the `nobots` keyword,
for example `bomb.gz` in the example below.  Since this is a third party directive, you have to tell Caddy when to add
the directive using the global `order` setting. A full example can be found in [Caddyfile](./Caddyfile).

Then you can specify user agent either as strings or regular expressions. When using regular expressions you must add
the `regexp` keyword in front of the regex.

Caddyfile example:

```
{
	order nobots after header
}

nobots "bomb.gz" {
  "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
  "DuckDuckBot"
  regexp "^[Bb]ot"
  regexp "bingbot"
}
```

There is another keyword that is useful in case you want to allow crawlers and bots navigate through specific parts of
your website. The keyword is `public` and its values are regular expressions, so you can use it as following:

```
nobots "bomb.gz" {
  "Googlebot/2.1 (+http://www.googlebot.com/bot.html)"
  public "^/public"
  public "^/[a-z]{,5}/public"
}
```

The above example will send the bot to all URIs except those that match with `/public` and `[a-z]{,5}/public`.

NOTE: By default all URIs.

Three more keywords control logging:

```
nobots "bomb.gz" {
  showHits
  showMisses
  showPublic
}
```

`showHits` will log blocked user-agents, while `showMisses` will show unblocked user-agents (useful for debugging).
Finally, `showPublic` will display access to public URIs.


## How to create a bomb

The bomb is not provided within the plugin so you have to create one. On Linux this is really easy, you can use the
following commands.

```
dd if=/dev/zero bs=1M count=1024 | gzip > 1G.gzip
dd if=/dev/zero bs=1M count=10240 | gzip > 10G.gzip
dd if=/dev/zero bs=1M count=1048576 | gzip > 1T.gzip
```

To optimize the final bomb you may compress the parts several times:

```
cat 10G.gzip | gzip > 10G.gzipx2
cat 1T.gzip | gzip | gzip | gzip > 1T.gzipx4
 ```
*NOTE*: The extension `.gzipx2` or `.gzipx4` is only to highlight how many times the file was compressed.

## Testing the Module

Download or create the [Caddyfile](./Caddyfile) used as an example (all logging is turned on in this file).

Compile your custom Caddy server using:

```shell
xcaddy build --with github.com/mkalus/caddy_block_aws
```

And run it:

```shell
./caddy run
```

You can now test access to the server, e.g. using curl:

```shell
# nice agents
curl localhost:2015
curl -H "User-Agent: NiceAgents Number One" localhost:2015
# evil agents
curl -H "User-Agent: DuckDuckBot" localhost:2015
curl -H "User-Agent: Googlebot/2.1 (+http://www.googlebot.com/bot.html)" localhost:2015
# public access
curl localhost:2015/public
curl -H "User-Agent: DuckDuckBot" localhost:2015/public
```
