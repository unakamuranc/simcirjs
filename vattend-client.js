// vattend (Django IdP) 連携: OAuth2 Authorization Code + PKCE と回路保存 API
var vattend = (function() {

  var BASE = 'https://arkwakl.xyz/vattend';
  var CLIENT_ID = 'simcirjs';
  var SCOPE = 'read write';
  var KEY_TOKENS = 'vattend.tokens';
  var KEY_PKCE = 'vattend.pkce';

  var redirectUri = function() {
    return location.origin + location.pathname;
  };

  var b64url = function(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i += 1) { s += String.fromCharCode(bytes[i]); }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };

  var randomString = function(len) {
    var a = new Uint8Array(len);
    crypto.getRandomValues(a);
    return b64url(a);
  };

  var sha256 = function(text) {
    return crypto.subtle.digest('SHA-256', new TextEncoder().encode(text) ).
      then(function(buf) { return b64url(new Uint8Array(buf) ); });
  };

  var loadTokens = function() {
    try { return JSON.parse(localStorage.getItem(KEY_TOKENS) ); } catch(e) { return null; }
  };

  var saveTokens = function(t) {
    var tokens = {
      access_token: t.access_token,
      refresh_token: t.refresh_token || (loadTokens() || {}).refresh_token,
      expires_at: Date.now() + (t.expires_in - 30) * 1000
    };
    localStorage.setItem(KEY_TOKENS, JSON.stringify(tokens) );
    return tokens;
  };

  var tokenRequest = function(params) {
    return fetch(BASE + '/o/token/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params).toString()
    }).then(function(res) {
      if (!res.ok) { throw new Error('token request failed: ' + res.status); }
      return res.json();
    }).then(saveTokens);
  };

  var login = function() {
    var verifier = randomString(48);
    var state = randomString(16);
    sessionStorage.setItem(KEY_PKCE, JSON.stringify({ verifier: verifier, state: state }) );
    return sha256(verifier).then(function(challenge) {
      location.href = BASE + '/o/authorize/?' + new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID,
        redirect_uri: redirectUri(),
        scope: SCOPE,
        state: state,
        code_challenge: challenge,
        code_challenge_method: 'S256'
      }).toString();
    });
  };

  var logout = function() {
    var t = loadTokens();
    localStorage.removeItem(KEY_TOKENS);
    if (t && t.access_token) {
      // best effort
      fetch(BASE + '/o/revoke_token/', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ token: t.access_token, client_id: CLIENT_ID }).toString()
      }).catch(function() {});
    }
  };

  // 認可後のリダイレクトで戻ってきた場合に code をトークンへ交換する。
  var handleRedirect = function() {
    var q = new URLSearchParams(location.search);
    if (!q.has('code') && !q.has('error') ) { return Promise.resolve(false); }
    history.replaceState(null, '', redirectUri() );
    var saved = null;
    try { saved = JSON.parse(sessionStorage.getItem(KEY_PKCE) ); } catch(e) {}
    sessionStorage.removeItem(KEY_PKCE);
    if (q.has('error') ) { return Promise.reject(new Error(q.get('error') ) ); }
    if (!saved || saved.state !== q.get('state') ) {
      return Promise.reject(new Error('invalid state') );
    }
    return tokenRequest({
      grant_type: 'authorization_code',
      code: q.get('code'),
      redirect_uri: redirectUri(),
      client_id: CLIENT_ID,
      code_verifier: saved.verifier
    }).then(function() { return true; });
  };

  var getAccessToken = function() {
    var t = loadTokens();
    if (!t) { return Promise.resolve(null); }
    if (Date.now() < t.expires_at) { return Promise.resolve(t.access_token); }
    if (!t.refresh_token) { localStorage.removeItem(KEY_TOKENS); return Promise.resolve(null); }
    return tokenRequest({
      grant_type: 'refresh_token',
      refresh_token: t.refresh_token,
      client_id: CLIENT_ID
    }).then(function(n) { return n.access_token; }, function() {
      localStorage.removeItem(KEY_TOKENS);
      return null;
    });
  };

  var api = function(method, path, body) {
    return getAccessToken().then(function(token) {
      if (!token) { throw new Error('not logged in'); }
      var opts = { method: method, cache: 'no-store', headers: { Authorization: 'Bearer ' + token } };
      if (body !== undefined) {
        opts.headers['Content-Type'] = 'application/json';
        opts.body = JSON.stringify(body);
      }
      return fetch(BASE + '/api' + path, opts);
    }).then(function(res) {
      if (res.status === 401 || res.status === 403) {
        localStorage.removeItem(KEY_TOKENS);
        throw new Error('not logged in');
      }
      return res.json().then(function(json) {
        if (!res.ok) { throw new Error(json.error || ('HTTP ' + res.status) ); }
        return json;
      });
    });
  };

  return {
    login: login,
    logout: logout,
    handleRedirect: handleRedirect,
    isLoggedIn: function() { return !!loadTokens(); },
    me: function() { return api('GET', '/me/'); },
    list: function() { return api('GET', '/circuits/').then(function(r) { return r.circuits; }); },
    get: function(id) { return api('GET', '/circuits/' + id + '/'); },
    save: function(name, data) { return api('POST', '/circuits/save/', { name: name, data: data }); },
    remove: function(id) { return api('DELETE', '/circuits/' + id + '/'); }
  };
}());
