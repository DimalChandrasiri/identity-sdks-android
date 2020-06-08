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

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import net.openid.appauth.AuthState;
import org.json.JSONException;
import org.json.JSONObject;
import org.oidc.agent.util.Constants;

import static net.openid.appauth.Preconditions.checkNotEmpty;

public class UserInfoState extends AuthState {

    public UserInfoState() {
        super();
    }

    private UserInfoResponse mLastUserInfoResponse;

    private OIDCDiscoveryResponse mLastDiscoveryResponse;

    public void update(@Nullable UserInfoResponse userInfoResponse) {
        mLastUserInfoResponse = userInfoResponse;
    }

    public UserInfoResponse getLastUserInfoResponse() {
        return mLastUserInfoResponse;
    }

    public void update(@Nullable OIDCDiscoveryResponse discoveryResponse) {
        mLastDiscoveryResponse = discoveryResponse;
    }

    public OIDCDiscoveryResponse getLastDiscoveryResponse() {
        return mLastDiscoveryResponse;
    }

    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    public JSONObject jsonSerialize() {
        JSONObject json = new JSONObject();
        if (mLastUserInfoResponse != null) {
            put(json, Constants.KEY_LAST_USERINFO_RESPONSE,
                    mLastUserInfoResponse.getUserInfoProperties());
        }
        return json;
    }

    public static UserInfoState jsonDeserialize(@NonNull String jsonStr) throws JSONException {
        checkNotEmpty(jsonStr, "jsonStr cannot be null or empty");
        return jsonDeserialize(new JSONObject(jsonStr));
    }

    public static UserInfoState jsonDeserialize(JSONObject json) {

        UserInfoState state = new UserInfoState();
        Log.i("User Info State", json.toString());
        if (json.has(Constants.KEY_LAST_USERINFO_RESPONSE)) {
            try {
                state.mLastUserInfoResponse = UserInfoResponse.jsonDeserialize(json);

            } catch (JSONException e) {
                e.printStackTrace();
            }

        }
        return state;
    }

    public static void put(@NonNull JSONObject json, @NonNull String field,
            @NonNull JSONObject value) {

        try {
            json.put(field, value);
        } catch (JSONException ex) {
            throw new IllegalStateException("JSONException thrown", ex);
        }
    }

}
