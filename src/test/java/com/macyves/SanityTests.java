/**
 * Simple curl-like syntax wrapper based on Apache Httpcomponent Httpclient.
 * 
 * Yves Hwang, 23.10.2014
 * http://macyves.wordpress.com
 * 
 */
package com.sfr.integration.http;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import com.macyves.http.client.Curl;

public class SanityTests {

    @Test
    public void curl_sanity() {
        Curl curl = new Curl("www.google.no", 80, true, false);
        assertEquals(200, curl.issueRequestWithHeaders("GET", "/", null));
    }
}