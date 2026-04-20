/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2026 Kai Kramer
 *
 * This file is part of KeyStore Explorer.
 *
 * KeyStore Explorer is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * KeyStore Explorer is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with KeyStore Explorer.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.kse.utilities.net;

import static java.util.Collections.singletonList;
import static org.kse.utilities.net.PacHelperFunctions.alert;
import static org.kse.utilities.net.PacHelperFunctions.dateRange;
import static org.kse.utilities.net.PacHelperFunctions.dnsDomainIs;
import static org.kse.utilities.net.PacHelperFunctions.dnsDomainLevels;
import static org.kse.utilities.net.PacHelperFunctions.dnsResolve;
import static org.kse.utilities.net.PacHelperFunctions.isInNet;
import static org.kse.utilities.net.PacHelperFunctions.isPlainHostName;
import static org.kse.utilities.net.PacHelperFunctions.isResolvable;
import static org.kse.utilities.net.PacHelperFunctions.localHostOrDomainIs;
import static org.kse.utilities.net.PacHelperFunctions.myIpAddress;
import static org.kse.utilities.net.PacHelperFunctions.shExpMatch;
import static org.kse.utilities.net.PacHelperFunctions.timeRange;
import static org.kse.utilities.net.PacHelperFunctions.weekdayRange;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.StringTokenizer;

import org.mozilla.javascript.BaseFunction;
import org.mozilla.javascript.Context;
import org.mozilla.javascript.Function;
import org.mozilla.javascript.Scriptable;
import org.mozilla.javascript.ScriptableObject;

/**
 * Proxy Selector for Proxy Automatic Configuration (PAC).
 */
public class PacProxySelector extends ProxySelector {
    private static final ResourceBundle res = ResourceBundle.getBundle("org/kse/utilities/net/resources");

    private Scriptable pacScope;
    private final URI pacURI;
    private final Map<URI, List<Proxy>> uriToProxiesCache = new HashMap<>();


    /**
     * Construct PacProxySelector using an Automatic proxy configuration URL.
     * Loads the PAC script from the supplied URL.
     *
     * @param pacURI Automatic proxy configuration URL
     */
    public PacProxySelector(URI pacURI) {
        if (pacURI == null) {
            throw new IllegalArgumentException("PAC URL is missing");
        }

        this.pacURI = pacURI;

        // As load and compile of pac scripts is time-consuming we do this on first call to select
    }

    /**
     * Get a list of proxies for the supplied URI.
     *
     * @param uri The URI that a connection is required to
     * @return List of proxies; if there are any issues with the PAC returns 'no proxy'
     */
    @Override
    public List<Proxy> select(URI uri) {
        if (pacScope == null) {
            try {
                pacScope = compilePacScript(loadPacScript(pacURI));
            } catch (PacProxyException ex) {
                ex.printStackTrace();
                return singletonList(Proxy.NO_PROXY);
            }
        }

        if (uriToProxiesCache.containsKey(uri)) {
            return uriToProxiesCache.get(uri);
        }

        String pacFunctionReturn = null;

        try (Context cx = Context.enter()) {
            cx.setClassShutter(className -> false);
            Object func = ScriptableObject.getProperty(pacScope, "FindProxyForURL");

            if (func instanceof Function) {
                Object[] args = { uri.toString(), uri.getHost() };
                Object result = ((Function) func).call(cx, pacScope, pacScope, args);
                pacFunctionReturn = Context.toString(result);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
            return singletonList(Proxy.NO_PROXY);
        }

        if (pacFunctionReturn == null) {
            return singletonList(Proxy.NO_PROXY);
        }

        List<Proxy> proxies = new ArrayList<>(parsePacProxies(pacFunctionReturn));

        if (proxies.isEmpty()) {
            proxies.add(Proxy.NO_PROXY);
        }

        uriToProxiesCache.put(uri, proxies);

        return proxies;
    }

    private String loadPacScript(URI pacURI) throws PacProxyException {
        URLConnection connection = null;

        // Save existing default proxy selector...
        ProxySelector defaultProxySelector = ProxySelector.getDefault();

        try {
            // ...and set use of no proxy selector. We don't want to try and use any proxy to get the pac script
            ProxySelector.setDefault(new NoProxySelector());

            URL latestVersionUrl = pacURI.toURL();
            connection = latestVersionUrl.openConnection();

            try (InputStream is = connection.getInputStream()) {
                return new String(is.readAllBytes());
            }
        } catch (IOException ex) {
            throw new PacProxyException(
                    MessageFormat.format(res.getString("NoLoadPacScript.exception.message"), pacURI), ex);
        } finally {
            // Restore saved default proxy selector
            ProxySelector.setDefault(defaultProxySelector);

            if ((connection instanceof HttpURLConnection)) {
                ((HttpURLConnection) connection).disconnect();
            }
        }
    }

    private static String argAsString(Object[] args, int index) {
        return args.length > index ? Context.toString(args[index]) : null;
    }

    private static String argAsString(Object[] args, int index, String defaultValue) {
        return args.length > index ? Context.toString(args[index]) : defaultValue;
    }

    private static void put(Scriptable scope, String name, java.util.function.Function<Object[], Object> fn) {
        ScriptableObject.putProperty(scope, name, new BaseFunction() {
            @Override
            public Object call(Context cx, Scriptable scope, Scriptable thisObj, Object[] args) {
                return fn.apply(args);
            }
        });
    }

    private Scriptable compilePacScript(String pacScript) throws PacProxyException {
        try (Context cx = Context.enter()) {
            cx.setClassShutter(className -> false);
            Scriptable scope = cx.initStandardObjects();

            put(scope, "alert", args -> { alert(argAsString(args, 0, "")); return Context.getUndefinedValue(); });
            put(scope, "dnsDomainIs", args -> dnsDomainIs(argAsString(args, 0), argAsString(args, 1)));
            put(scope, "dnsDomainLevels", args -> dnsDomainLevels(argAsString(args, 0)));
            put(scope, "dnsResolve", args -> dnsResolve(argAsString(args, 0)));
            put(scope, "isResolvable", args -> isResolvable(argAsString(args, 0)));
            put(scope, "myIpAddress", args -> myIpAddress());
            put(scope, "isPlainHostName", args -> isPlainHostName(argAsString(args, 0)));
            put(scope, "localHostOrDomainIs", args -> localHostOrDomainIs(argAsString(args, 0), argAsString(args, 1)));
            put(scope, "shExpMatch", args -> shExpMatch(argAsString(args, 0), argAsString(args, 1, "")));
            put(scope, "isInNet", args -> isInNet(argAsString(args, 0), argAsString(args, 1), argAsString(args, 2)));
            put(scope, "dateRange", args -> dateRange(args));
            put(scope, "weekdayRange", args -> weekdayRange(args));
            put(scope, "timeRange", args -> timeRange(args));

            cx.evaluateString(scope, pacScript, "pac", 1, null);
            return scope;
        } catch (Exception ex) {
            throw new PacProxyException(res.getString("NoCompilePacScript.exception.message"), ex);
        }
    }

    private List<Proxy> parsePacProxies(String pacFunctionReturn) {
        ArrayList<Proxy> proxies = new ArrayList<>();

        // PAC function return delimits different proxies by ';'
        StringTokenizer strTok = new StringTokenizer(pacFunctionReturn, ";");

        while (strTok.hasMoreTokens()) {
            String pacFunctionReturnElement = strTok.nextToken().trim();

            if (!pacFunctionReturnElement.isEmpty()) {
                Proxy proxy = parsePacProxy(pacFunctionReturnElement);

                if (proxy != null) {
                    proxies.add(proxy);
                }
            }
        }

        return proxies;
    }

    private Proxy parsePacProxy(String pacProxy) {
        String[] split = pacProxy.split(" ", 0);

        String proxyTypeStr = split[0];
        Proxy.Type proxyType = null;

        switch (proxyTypeStr) {
        case "DIRECT":
            return Proxy.NO_PROXY;
        case "PROXY":
        case "HTTP":
        case "HTTPS":
            proxyType = Proxy.Type.HTTP;
            break;
        case "SOCKS":
        case "SOCKS4":
        case "SOCKS5":
            proxyType = Proxy.Type.SOCKS;
            break;
        default:
            return null;
        }

        if (split.length != 2) {
            return null;
        }

        String address = split[1];
        split = address.split(":", 0);
        String host = null;
        int port = 80;

        if (split.length == 1) {
            host = split[0];
        } else if (split.length == 2) {
            host = split[0];

            try {
                port = Integer.parseInt(split[1]);
            } catch (NumberFormatException ex) {
                return null;
            }
        } else {
            return null;
        }

        return new Proxy(proxyType, new InetSocketAddress(host, port));
    }

    /**
     * Connection failed. Do nothing.
     *
     * @param uri           The URI that the proxy at socketAddress failed to serve
     * @param socketAddress The socket address of the proxy/SOCKS server
     * @param ioException   The I/O exception thrown when the connection failed
     */
    @Override
    public void connectFailed(URI uri, SocketAddress socketAddress, IOException ioException) {
        /*
         * Do nothing. Documentation of base class ProxySelector suggests that
         * this method may be used to affect what the select method returns.
         * This is not relevant to us.
         */
    }

    /**
     * Get Automatic proxy configuration URL.
     *
     * @return PAC URI
     */
    public URI getPacURI() {
        return pacURI;
    }

    /**
     * Is this PacProxySelector object equal to another object?
     *
     * @param object Object to compare PacProxySelector with.
     * @return true if the equal, false otherwise.
     */
    @Override
    public boolean equals(Object object) {
        if (object == this) {
            return true;
        }

        if (!(object instanceof PacProxySelector)) {
            return false;
        }

        PacProxySelector cmpPacProxySelector = (PacProxySelector) object;

        return this.getPacURI().equals(cmpPacProxySelector.getPacURI());
    }
}
