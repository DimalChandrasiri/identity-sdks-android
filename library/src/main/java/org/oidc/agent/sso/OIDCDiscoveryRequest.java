/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.oidc.agent.sso;

import android.os.AsyncTask;
import android.util.Log;

import okio.Okio;
import org.json.JSONException;
import org.json.JSONObject;
import org.oidc.agent.exception.ClientException;
import org.oidc.agent.exception.ServerException;
import org.oidc.agent.util.Constants;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.Charset;

/**
 * Handles the OIDC Discovery request flow to Identity Server.
 */
public class OIDCDiscoveryRequest extends AsyncTask<Void, Void, OIDCDiscoveryResponse> {

    private String mDiscoveryEndpoint;
    private OIDCDiscoveryRespCallback mCallback;
    private static final String LOG_TAG = "OIDCDiscoveryRequest";
    private Exception exception;
    private OIDCDiscoveryResponse discoveryResponse;

    OIDCDiscoveryRequest(String discoveryEndpoint, OIDCDiscoveryRespCallback callback) {
        this.mDiscoveryEndpoint = discoveryEndpoint;
        this.mCallback = callback;

    }

    @Override
    protected OIDCDiscoveryResponse doInBackground(Void... voids) {

        OIDCDiscoveryResponse response = null;
        try {
            response = callDiscoveryUri();
        } catch (ServerException e) {
            e.printStackTrace();
        } catch (ClientException e) {
            e.printStackTrace();
        }
        return response;
    }

    /**
     * Call discovery endpoint of Identity Server.
     *
     * @return OAuthDiscovery.
     * @throws ServerException
     * @throws ClientException
     */
    private OIDCDiscoveryResponse callDiscoveryUri() throws ServerException, ClientException {

        HttpURLConnection conn;
        URL discoveryEndpoint;

        try {
            Log.d(LOG_TAG, "Call discovery service of identity server via: " + mDiscoveryEndpoint);
            discoveryEndpoint = new URL(mDiscoveryEndpoint);
            conn = (HttpURLConnection) discoveryEndpoint.openConnection();
            conn.setRequestMethod(Constants.HTTP_GET);
            conn.setDoInput(true);
            String response = Okio.buffer(Okio.source(conn.getInputStream()))
                    .readString(Charset.forName("UTF-8"));
            conn.disconnect();
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                Log.e(LOG_TAG, "Server returns" + conn.getResponseCode() + "when "
                        + "calling discovery endpoint");
                throw new ServerException("Server returns" + conn.getResponseCode() + "when "
                        + "calling discovery endpoint");
            }
            JSONObject jsonResponse = new JSONObject(response);
            discoveryResponse = new OIDCDiscoveryResponse(jsonResponse);
            Log.i(LOG_TAG, discoveryResponse.getLogoutEndpoint().toString());
            return discoveryResponse;

        } catch (MalformedURLException e) {
            exception = e;
            throw new ClientException("Discovery endpoint is malformed. ", e);
        } catch (IOException e) {
            exception = e;
            throw new ServerException("Error while calling the discovery endpoint. ", e);
        } catch (JSONException e) {
            exception = e;
            throw new ServerException("Error while parsing the discovery response as JSON. ", e);
        }
    }

    protected void onPostExecute(OIDCDiscoveryResponse response) {

        if (exception != null) {
            Log.i(LOG_TAG, "Test");
            mCallback.onDiscoveryRequestCompleted(exception, null);
        } else {
            mCallback.onDiscoveryRequestCompleted(null, response);
        }
    }

    /**
     * Interface to handle token response.
     */
    public interface OIDCDiscoveryRespCallback {

        /**
         * Handle the flow after token request is completed.
         */
        void onDiscoveryRequestCompleted(Exception e, OIDCDiscoveryResponse oidcDiscoveryResponse);
    }
}
