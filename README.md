# capybari-analyzer-web-tech

**Capybari Source Intelligence: Website Technology Detector: what is this site built with?**

Using only the page the Website Snapshot already fetched, it detects about 75 technologies:

- web servers, CDNs and hosting (Nginx, Apache, IIS, Cloudflare, CloudFront, Fastly, Vercel, Netlify, …)
- languages and frameworks (PHP, ASP.NET, Express, Next.js, Nuxt, Django, Rails, Laravel, …)
- front-end libraries with versions (React, Vue, Angular/AngularJS, jQuery, Bootstrap, Lodash, Moment.js, …)
- CMS, e-commerce and site builders, **including AI site builders** (WordPress, Shopify, Webflow, Wix, Framer, Lovable, v0, Bolt.new, …)
- analytics, marketing, payments and CAPTCHAs

It also flags:

- **end-of-life** components, from the shared lifecycle table in `capybari-core`
- **front-end libraries with known vulnerabilities**, looked up on OSV.dev (only library names and versions are sent)
- **stale-site signals**, such as a copyright notice that has not changed for 3+ years

| | |
|---|---|
| Requires | `web-snapshot` |
| Provides | `technologies` evidence |
| Scores | Technology Currency; vulnerable libraries count toward Security |
| Network | optional: `api.osv.dev` (library names + versions) |
| Rules | [`rules/signatures.yaml`](rules/signatures.yaml) |

```bash
go run ./cmd/capybari-web-tech https://example.com
```

## License

Apache-2.0
