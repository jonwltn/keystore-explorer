/*
 * Copyright 2004 - 2013 Wayne Grant
 *           2013 - 2025 Kai Kramer
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

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Contains constants for all URLs used by KSE
 */
public class URLs {

    private URLs() {
    }

    // general project URLs
    public static final String KSE_WEB_SITE = "https://keystore-explorer.org";
    public static final String KSE_USER_MANUAL = "https://keystore-explorer.org/doc/";
    public static final String GITHUB_PROJECT = "https://github.com/kaikramer/keystore-explorer";
    public static final String GITHUB_ISSUE_TRACKER = "https://github.com/kaikramer/keystore-explorer/issues";

    // for update checks and download of latest version
    public static final String LATEST_VERSION_ADDRESS = "https://keystore-explorer.org/version.txt";
    public static final String DOWNLOADS_WEB_ADDRESS = "https://keystore-explorer.org/downloads.html";

    // URL of page that forwards to unlimited strength policy download site for the respective Java version
    public static final String JCE_POLICY_DOWNLOAD_URL = "https://keystore-explorer.org/jcePolicyDownload" +
                                                         ".html?jreversion={0}";

    // list of contributors
    public static final String KSE_WEBSITE_CONTRIBUTORS = "https://keystore-explorer.org/contribute.html#contributions";

    // list of TSA servers for sign jar dialog
    public static final String[] TSA_URLS = new String[] { "http://timestamp.digicert.com",
                                                           "http://tsa.quovadisglobal.com/TSS/HttpTspServer",
                                                           "http://rfc3161timestamp.globalsign.com/advanced",
                                                           "http://time.certum.pl",
                                                           "http://timestamp.acs.microsoft.com",
                                                           "http://timestamp.sectigo.com" };


    /**
     * Use regular expression to evaluate allowable URL
     *
     * @param url String to check
     * @return True if allowed
     */
    public static boolean isValidUrl(String url) {
        String regex = "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$";
        Pattern pattern = Pattern.compile(regex, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(url);
        return matcher.find();
    }
}
