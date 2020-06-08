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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import net.openid.appauth.AuthState;
import org.json.JSONObject;

public class UserInfoState extends AuthState {

    public UserInfoState() {
        super();
    }

    private UserInfoResponse mLastUserInfoResponse;

    public void update(@Nullable UserInfoResponse userInfoResponse) {
        mLastUserInfoResponse = userInfoResponse;
    }

    public UserInfoResponse getLastUserInfoResponse() {
        return mLastUserInfoResponse;
    }

    public String jsonSerializeString() {
        return jsonSerialize().toString();
    }

    public JSONObject jsonSerialize() {
        return mLastUserInfoResponse.getUserInfoProperties();
    }
}
