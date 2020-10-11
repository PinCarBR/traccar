/*
 * Copyright 2015 - 2017 Anton Tananaev (anton@traccar.org)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.traccar.api.resource;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.traccar.Context;
import org.traccar.api.BaseResource;
import org.traccar.helper.LogAction;
import org.traccar.model.User;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.sql.SQLException;

@Path("webhook/okta")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class WebhookOktaResource extends BaseResource {

    private static final Logger LOGGER = LoggerFactory.getLogger(WebhookOktaResource.class);

    @Path("event")
    @GET
    public Response get(@HeaderParam("X-Okta-Verification-Challenge") String verificationChallenge) {
        if (verificationChallenge != null) {
            return Response.status(Response.Status.OK)
                    .entity(String.format("{ \"verification\" : \"%s\" }", verificationChallenge))
                    .build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("No verification challenge")
                    .build();
        }
    }

    @Path("event")
    @POST
    public Response add(String body) throws SQLException {
        if (Context.getPermissionsManager().getUserAdmin(getUserId())) {
            try {
                JsonNode eventNode = Context.getObjectMapper().readTree(body);
                String email = eventNode.get("data")
                        .get("events").get(0)
                        .get("target").get(0)
                        .get("alternateId")
                        .textValue();
                String displayName = eventNode.get("data")
                        .get("events").get(0)
                        .get("target").get(0)
                        .get("displayName")
                        .textValue();
                User user = Context.getDataManager().getUserByEmail(email);
                if (user != null) {
                    user.setName(displayName);
                    User before = Context.getPermissionsManager().getUser(user.getId());
                    Context.getPermissionsManager().checkUserUpdate(getUserId(), before, user);
                    Context.getPermissionsManager().checkPermission(User.class, getUserId(), user.getId());
                    Context.getManager(User.class).updateItem(user);
                    LogAction.edit(getUserId(), user);
                    return Response.status(Response.Status.OK)
                            .entity(user)
                            .build();
                } else {
                    return Response.status(Response.Status.BAD_REQUEST)
                            .entity("User not found")
                            .build();
                }
            } catch (JsonProcessingException e) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity(e)
                        .build();
            }
        } else {
            throw new SecurityException("Admin access required");
        }
    }
}
