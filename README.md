# OAuth 2.0 explained

Idea: Use Flask to represent each role. Explain using an IPython notebook

###### Work in progress

---

### References

- [**OAuth 2.0 Framework** - RFC 6749](http://tools.ietf.org/html/rfc6749)
- [**Bearer Token Usage** - RFC 6750](http://tools.ietf.org/html/rfc6750)
- [**Threat Model and Security Considerations** - RFC 6819](http://tools.ietf.org/html/rfc6819)
- [More???... **OAuth 2.0**](https://oauth.net/2/)

---

### What's next?

- [ ] Complete the client app code
- [ ] Create the resource owner, authorization server and resource server (one *Flask* app is enought)
- [ ] Talk about possible attacks
- [ ] Simple explanation? Maybe draw something, a comic?

### Ideas and Qs

* Maybe avoid using a session to store `state`? Depends if `session` is stored client side or server side
