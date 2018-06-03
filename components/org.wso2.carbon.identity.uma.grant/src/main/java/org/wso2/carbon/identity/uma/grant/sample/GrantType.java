/*
 * Copyright (c) 2018, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.uma.grant.sample;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.oauth.uma.common.exception.UMAClientException;
import org.wso2.carbon.identity.oauth.uma.common.exception.UMAServerException;
import org.wso2.carbon.identity.oauth.uma.permission.service.dao.PermissionTicketDAO;
import org.wso2.carbon.identity.oauth.uma.permission.service.model.Resource;
import org.wso2.carbon.identity.oauth.uma.xacml.service.handler.XACMLUMAHandler;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.ResponseHeader;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.handlers.grant.AbstractAuthorizationGrantHandler;

import java.util.List;

/**
 * Grant type for User Managed Access.
 */
public class GrantType extends AbstractAuthorizationGrantHandler {

    private static Log log = LogFactory.getLog(GrantType.class);
    public static final String UMA_GRANT_PARAM = "grantType";
    public static final String PERMISSION_TICKET = "permissionTicket";
    boolean authStatus = false;

    @Override
    public boolean validateGrant(OAuthTokenReqMessageContext tokReqMsgCtx) throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("In GrantType validateGrant method.");
        }
        if (!super.validateGrant(tokReqMsgCtx)) {
            return false;
        }

        //extract clientId from the tokenReqMessageContext
        String clientId = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getClientId();

        // extract request parameters
        RequestParameter[] parameters = tokReqMsgCtx.getOauth2AccessTokenReqDTO().getRequestParameters();

        String grantType = null;
        String permissionTicket = null;
        boolean isMatched = false;

        // find out grant type
        for (RequestParameter parameter : parameters) {
            if (UMA_GRANT_PARAM.equals(parameter.getKey())) {
                if (parameter.getValue() != null) {
                    grantType = parameter.getValue()[0];
                }
            }

            // find out permission ticket
            if (PERMISSION_TICKET.equals(parameter.getKey())) {
                if (PERMISSION_TICKET.equals(parameter.getKey())) {
                    if (parameter.getValue() != null) {
                        permissionTicket = parameter.getValue()[0];
                        log.info("Obtained permission ticket");
                        isMatched = true;
                    }
                }
            }
        }

        if (grantType != null) {

            //validate grant type and permission ticket
            authStatus = isValidGrantType(grantType, permissionTicket, clientId);

            if (authStatus) {

                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setUserName(grantType);
                tokReqMsgCtx.setAuthorizedUser(authenticatedUser);
                tokReqMsgCtx.setScope(tokReqMsgCtx.getOauth2AccessTokenReqDTO().getScope());

            } else {

                ResponseHeader responseHeader = new ResponseHeader();
                responseHeader.setKey("SampleHeader-999");
                responseHeader.setValue("Provided details are invalid.");
                tokReqMsgCtx.addProperty("RESPONSE_HEADERS", new ResponseHeader[]{responseHeader});
            }
        }
        return authStatus;
    }

    /**
     * @param grantType
     * @param permissionTicket
     * @return
     */
    private boolean isValidGrantType(String grantType, String permissionTicket, String clientId) throws
            IdentityOAuth2Exception {

        XACMLUMAHandler xacmlumaHandler = new XACMLUMAHandler();
        boolean isCheck = true;

        PermissionTicketDAO permissionTicketDAO = new PermissionTicketDAO();
        List<Resource> resources = null;

        try {
            if (grantType.equals("urn:ietf:params:oauth:grant-type:uma-ticket")) {
                resources = permissionTicketDAO.validatePermissionTicket(permissionTicket);
                log.info("Valid permission ticket :" + permissionTicket);
                if (xacmlumaHandler.isAuthorized(resources, clientId)) {
                    if (log.isDebugEnabled()) {
                        log.debug("Invalid permission ticket. :\n" + permissionTicket + clientId);
                    }
                    log.info("Resource get authorized.");
                    return true;
                }
            }
        } catch (UMAClientException e) {

            if (log.isDebugEnabled()) {
                log.debug("Invalid permission ticket. :\n" + permissionTicket + clientId);
            }
            return false;

        } catch (UMAServerException e) {

            if (log.isDebugEnabled()) {
                log.debug("Server error occurred. :\n" + permissionTicket + clientId);
            }

            return false;

        }
        return isCheck;
    }
}
