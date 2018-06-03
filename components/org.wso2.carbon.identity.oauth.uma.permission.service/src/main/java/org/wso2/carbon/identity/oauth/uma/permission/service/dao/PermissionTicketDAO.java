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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth.uma.permission.service.dao;

import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.oauth.uma.common.UMAConstants;
import org.wso2.carbon.identity.oauth.uma.common.exception.UMAClientException;
import org.wso2.carbon.identity.oauth.uma.common.exception.UMAServerException;
import org.wso2.carbon.identity.oauth.uma.permission.service.model.PermissionTicketModel;
import org.wso2.carbon.identity.oauth.uma.permission.service.model.Resource;
import org.wso2.carbon.identity.oauth2.util.NamedPreparedStatement;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * Data Access Layer functionality for Permission Endpoint. This includes storing requested permissions
 * (requested resource ids with their scopes).
 */
public class PermissionTicketDAO {

    private static final String STORE_PT_QUERY = "INSERT INTO IDN_PERMISSION_TICKET " +
            "(PT, TIME_CREATED, VALIDITY_PERIOD, TICKET_STATE, TENANT_ID) VALUES " +
            "(:" + UMAConstants.SQLPlaceholders.PERMISSION_TICKET + ";,:" + UMAConstants.SQLPlaceholders.TIME_CREATED +
            ";,:" + UMAConstants.SQLPlaceholders.VALIDITY_PERIOD + ";,:" + UMAConstants.SQLPlaceholders.STATE + ";,:" +
            UMAConstants.SQLPlaceholders.TENANT_ID + ";)";
    private static final String STORE_PT_RESOURCE_IDS_QUERY = "INSERT INTO IDN_PT_RESOURCE " +
            "(PT_RESOURCE_ID, PT_ID) VALUES " +
            "((SELECT ID FROM IDN_RESOURCE WHERE RESOURCE_ID = :" + UMAConstants.SQLPlaceholders.RESOURCE_ID + ";),:"
            + UMAConstants.SQLPlaceholders.ID + ";)";
    private static final String STORE_PT_RESOURCE_SCOPES_QUERY = "INSERT INTO IDN_PT_RESOURCE_SCOPE " +
            "(PT_RESOURCE_ID, PT_SCOPE_ID) VALUES (:" + UMAConstants.SQLPlaceholders.ID + ";, " +
            "(SELECT ID FROM IDN_RESOURCE_SCOPE WHERE SCOPE_NAME = :" + UMAConstants.SQLPlaceholders.RESOURCE_SCOPE
            + "; AND RESOURCE_IDENTITY = (SELECT ID FROM IDN_RESOURCE WHERE RESOURCE_ID = :" +
            UMAConstants.SQLPlaceholders.RESOURCE_ID + ";)))";
    private static final String VALIDATE_REQUESTED_RESOURCE_IDS_WITH_REGISTERED_RESOURCE_IDS = "SELECT ID " +
            "FROM IDN_RESOURCE WHERE RESOURCE_ID = :" + UMAConstants.SQLPlaceholders.RESOURCE_ID + "; AND " +
            "RESOURCE_OWNER_NAME = :" + UMAConstants.SQLPlaceholders.RESOURCE_OWNER_NAME + ";";
    private static final String VALIDATE_REQUESTED_RESOURCE_SCOPES_WITH_REGISTERED_RESOURCE_SCOPES = "SELECT ID FROM" +
            " IDN_RESOURCE_SCOPE WHERE SCOPE_NAME = :" + UMAConstants.SQLPlaceholders.RESOURCE_SCOPE + "; AND " +
            "RESOURCE_IDENTITY = (SELECT ID FROM IDN_RESOURCE WHERE RESOURCE_ID = :" +
            UMAConstants.SQLPlaceholders.RESOURCE_ID + ";)";
    private static final String VALIDATE_PERMISSION_TICKET = "SELECT PT FROM IDN_PERMISSION_TICKET WHERE PT = ? ;";
    public static final String RETRIEVE_RESOURCE_ID_STORE_IN_PT = "select RESOURCE_ID from IDN_RESOURCE inner join " +
            "IDN_PT_RESOURCE on IDN_RESOURCE.ID = IDN_PT_RESOURCE.PT_RESOURCE_ID inner join IDN_PERMISSION_TICKET " +
            "on IDN_PT_RESOURCE.PT_ID = IDN_PERMISSION_TICKET.ID where IDN_PERMISSION_TICKET.PT = ?;";

    public static final String RETRIEVE_RESOURCE_SCOPES_STORE_IN_PT = "select  SCOPE_NAME\n" +
            "from IDN_RESOURCE_SCOPE\n" +
            "inner join IDN_PT_RESOURCE_SCOPE\n" +
            "on IDN_RESOURCE_SCOPE.ID = IDN_PT_RESOURCE_SCOPE.PT_SCOPE_ID\n" +
            "inner join IDN_PT_RESOURCE\n" +
            "on IDN_PT_RESOURCE_SCOPE.PT_RESOURCE_ID = IDN_PT_RESOURCE.ID\n" +
            "inner join IDN_PERMISSION_TICKET\n" +
            "on IDN_PT_RESOURCE.PT_ID = IDN_PERMISSION_TICKET.ID\n" +
            "where IDN_PERMISSION_TICKET.PT = ?;";

    public static final String ResourceID = "select RESOURCE_ID from IDN_RESOURCE inner join IDN_RESOURCE_SCOPE" +
            "on IDN_RESOURCE.ID = IDN_RESOURCE_SCOPE.RESOURCE_IDENTITY;";
    /**
     * Issue a permission ticket. Permission ticket represents the resources requested by the resource server on
     * client's behalf
     *
     * @param resourceList          A list with the resource ids and the corresponding scopes.
     * @param permissionTicketModel Model class for permission ticket values.
     * @throws UMAServerException Exception thrown when there is a database issue.
     * @throws UMAClientException Exception thrown when there is an invalid resource ID/scope.
     */
    public static void persistPTandRequestedPermissions(List<Resource> resourceList,
                                                        PermissionTicketModel permissionTicketModel,
                                                        String resourceOwnerName) throws UMAClientException,
            UMAServerException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            checkResourceIdsExistence(connection, resourceList, resourceOwnerName);
            checkResourceScopesExistence(connection, resourceList);
            connection.setAutoCommit(false);
            NamedPreparedStatement ptNamedPreparedStatement = new NamedPreparedStatement(connection, STORE_PT_QUERY);
            ptNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.PERMISSION_TICKET,
                    permissionTicketModel.getTicket());
            ptNamedPreparedStatement.setTimeStamp(UMAConstants.SQLPlaceholders.TIME_CREATED,
                    new Timestamp(new Date().getTime()), permissionTicketModel.getCreatedTime());
            ptNamedPreparedStatement.setLong(UMAConstants.SQLPlaceholders.VALIDITY_PERIOD,
                    permissionTicketModel.getValidityPeriod());
            ptNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.STATE, permissionTicketModel.getStatus());
            ptNamedPreparedStatement.setLong(UMAConstants.SQLPlaceholders.TENANT_ID,
                    permissionTicketModel.getTenantId());
            try (PreparedStatement preparedStatement = ptNamedPreparedStatement.getPreparedStatement()) {
                preparedStatement.execute();

                // Checking if the PT is persisted in the db.
                long id;
                try (ResultSet resultSet = preparedStatement.getGeneratedKeys()) {
                    if (resultSet.next()) {
                        id = resultSet.getLong(1);
                    } else {
                        throw new UMAServerException(UMAConstants.ErrorMessages
                                .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_PT);
                    }
                }

                for (Resource resource : resourceList) {
                    NamedPreparedStatement resourceNamedPreparedStatement = new NamedPreparedStatement(connection,
                            STORE_PT_RESOURCE_IDS_QUERY);
                    resourceNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.RESOURCE_ID,
                            resource.getResourceId());
                    resourceNamedPreparedStatement.setLong(UMAConstants.SQLPlaceholders.ID, id);
                    try (PreparedStatement resourceIdStatement =
                                 resourceNamedPreparedStatement.getPreparedStatement()) {
                        resourceIdStatement.execute();
                        try (ResultSet resultSet = resourceIdStatement.getGeneratedKeys()) {
                            if (resultSet.next()) {
                                long resourceId = resultSet.getLong(1);
                                NamedPreparedStatement scopeNamedPreparedStatement = new NamedPreparedStatement
                                        (connection, STORE_PT_RESOURCE_SCOPES_QUERY);
                                scopeNamedPreparedStatement.setLong(UMAConstants.SQLPlaceholders.ID,
                                        resourceId);
                                try (PreparedStatement resourceScopeStatement =
                                             scopeNamedPreparedStatement.getPreparedStatement()) {
                                    for (String scope : resource.getResourceScopes()) {
                                        scopeNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.RESOURCE_ID,
                                                resource.getResourceId());
                                        scopeNamedPreparedStatement.setString(
                                                UMAConstants.SQLPlaceholders.RESOURCE_SCOPE, scope);
                                        scopeNamedPreparedStatement.getPreparedStatement().addBatch();
                                    }
                                    resourceScopeStatement.executeBatch();
                                }
                            }
                        }
                    }
                }
            }
            connection.commit();
        } catch (SQLException e) {
            throw new UMAServerException(UMAConstants.ErrorMessages
                    .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_REQUESTED_PERMISSIONS, e);
        }
    }

    private static void checkResourceIdsExistence(Connection connection, List<Resource> resourceList, String
            resourceOwnerName) throws UMAClientException, UMAServerException {

        for (Resource resource : resourceList) {
            try {
                NamedPreparedStatement resourceIdNamedPreparedStatement = new NamedPreparedStatement(connection,
                        VALIDATE_REQUESTED_RESOURCE_IDS_WITH_REGISTERED_RESOURCE_IDS);
                resourceIdNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.RESOURCE_OWNER_NAME,
                        resourceOwnerName);
                resourceIdNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.RESOURCE_ID,
                        resource.getResourceId());
                try (PreparedStatement resourceIdStatement = resourceIdNamedPreparedStatement.getPreparedStatement()) {
                    try (ResultSet resultSet = resourceIdStatement.executeQuery()) {
                        if (!resultSet.next()) {
                            throw new UMAClientException(UMAConstants.ErrorMessages
                                    .ERROR_BAD_REQUEST_INVALID_RESOURCE_ID, "Permission request failed with bad " +
                                    "resource ID : " + resource.getResourceId());
                        }
                    }
                }
            } catch (SQLException e) {
                throw new UMAServerException(UMAConstants.ErrorMessages
                        .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_REQUESTED_PERMISSIONS, e);
            }
        }
    }

    private static void checkResourceScopesExistence(Connection connection, List<Resource> resourceList) throws
            UMAClientException, UMAServerException {

        for (Resource resource : resourceList) {
            try {
                NamedPreparedStatement scopeNamedPreparedStatement = new NamedPreparedStatement
                        (connection, VALIDATE_REQUESTED_RESOURCE_SCOPES_WITH_REGISTERED_RESOURCE_SCOPES);
                scopeNamedPreparedStatement.setString(UMAConstants.SQLPlaceholders.RESOURCE_ID,
                        resource.getResourceId());
                try (PreparedStatement resourceScopeStatement =
                             scopeNamedPreparedStatement.getPreparedStatement()) {
                    for (String scope : resource.getResourceScopes()) {
                        scopeNamedPreparedStatement.setString(
                                UMAConstants.SQLPlaceholders.RESOURCE_SCOPE, scope);
                        try (ResultSet resultSet = resourceScopeStatement.executeQuery()) {
                            if (!resultSet.next()) {
                                throw new UMAClientException(UMAConstants.ErrorMessages
                                        .ERROR_BAD_REQUEST_INVALID_RESOURCE_SCOPE, "Permission request failed with " +
                                        "bad resource scope " + scope + " for resource " + resource.getResourceId());
                            }
                        }

                    }

                }
            } catch (SQLException e) {
                throw new UMAServerException(UMAConstants.ErrorMessages
                        .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_REQUESTED_PERMISSIONS, e);
            }
        }
    }

    /**
     * Validating permission Ticket and obtain resource id's and resource scopes which client requested.
     *
     * @param permissionTicket
     * @return resource
     * @throws UMAClientException
     * @throws UMAServerException
     */
    public List<Resource> validatePermissionTicket(String permissionTicket) throws UMAClientException,
            UMAServerException {

        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            try (PreparedStatement preparedStatement = connection.prepareStatement(VALIDATE_PERMISSION_TICKET)) {
                preparedStatement.setString(1, permissionTicket);
                try (ResultSet resultSet = preparedStatement.executeQuery()) {
                    if (!resultSet.next()) {
                        throw new UMAClientException(UMAConstants.ErrorMessages
                                .ERROR_BAD_REQUEST_INVALID_RESOURCE_ID);
                    } else {
                        /*retrieveResourceIdInPTicket(connection, permissionTicket);*/
                        List<Resource> list = retrieveResourceIdInPT(permissionTicket);
                        retrieveResourceScopesInPT(permissionTicket, list);
                        /*resource = retrieveResourceScopesInPT(permissionTicket,
                                retrieveResourceIdInPT(permissionTicket));*/
                        return list;

                    }
                }
            }
        } catch (SQLException e) {
            throw new UMAServerException(UMAConstants.ErrorMessages
                    .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_REQUESTED_PERMISSIONS, e);
        }
    }

    private static List<Resource> retrieveResourceIdInPT(String permissionTicket) throws UMAClientException,
            UMAServerException {

        Resource resource;
        List<Resource> resources = new ArrayList<Resource>();
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement preparedStatement = connection.prepareStatement(RETRIEVE_RESOURCE_ID_STORE_IN_PT);
            preparedStatement.setString(1, permissionTicket);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new UMAClientException(UMAConstants.ErrorMessages.
                        ERROR_BAD_REQUEST_INVALID_RESOURCE_ID_IN_PERMISSION_TICKET, "Permission request failed with"
                        + "invalid resource id's consist in permission ticket. ");
            } else {

                do {
                    resource = new Resource();
                    if (resultSet.getString(1) != null) {
                        resource.setResourceId(resultSet.getString(1));
                        resources.add(resource);
                    }

                } while (resultSet.next());

            }
        } catch (SQLException e) {
            throw new UMAServerException(UMAConstants.ErrorMessages
                    .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_REQUESTED_PERMISSIONS, e);
        }
        return resources;
    }

    private static List<Resource> retrieveResourceScopesInPT(String permissionTicket, List<Resource> resource)
            throws UMAClientException, UMAServerException {

        //Resource resource1;
        try (Connection connection = IdentityDatabaseUtil.getDBConnection()) {
            PreparedStatement preparedStatement = connection.prepareStatement(RETRIEVE_RESOURCE_SCOPES_STORE_IN_PT);
            preparedStatement.setString(1, permissionTicket);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new UMAClientException(UMAConstants.ErrorMessages.
                        ERROR_BAD_REQUEST_INVALID_RESOURCE_SCOPES_IN_PERMISSION_TICKET,
                        "Permission request failed with"
                                + "invalid resource scopes consist in permission ticket. ");
            } else {
                do {
                    for (Resource rr : resource) {
                        if (resultSet.getString(1) == rr.getResourceId()) {
                            if (!rr.getResourceScopes().contains(resultSet.getString(1))) {
                                rr.getResourceScopes().add(resultSet.getString(1));
                            }
                        }

                    }
                }
                while (resultSet.next());

            }
        } catch (SQLException e) {
            throw new UMAServerException(UMAConstants.ErrorMessages
                    .ERROR_INTERNAL_SERVER_ERROR_FAILED_TO_PERSIST_REQUESTED_PERMISSIONS, e);
        }
        return resource;
    }

}
