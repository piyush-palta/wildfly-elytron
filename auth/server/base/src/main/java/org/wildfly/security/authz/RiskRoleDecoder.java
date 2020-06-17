/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2020 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
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

package org.wildfly.security.authz;

import static org.wildfly.common.Assert.checkNotNullParam;

import java.io.*;
import java.net.Socket;
import java.util.*;
	

/**
 * A decoder to obtain role information using the source IP address runtime attribute from the identity, 
 * by analysing the risk associated with it
 * 
 */
public class RiskRoleDecoder implements RoleDecoder {

    private float riskScore;
    private String serverAddress;
    private Integer port;
    private Roles roles;


    /**
     * Construct a new instance.
     *
     * @param roles the roles to associate with the identity if the source IP address is within threshold risk
     * @param serverAddress the IP address of risk score server
     * @param port the port number of risk score server
     */
    public RiskRoleDecoder(Roles roles, String serverAddress, Integer port) {
        checkNotNullParam("roles", roles);
        this.riskScore=0.0;
        this.roles = roles;
        this.serverAddress = serverAddress;
        this.port=port;
    }
    

    /**
     * Calculate Risk Score based on the source address to make authorization decision
     *
     * @param sourceAddress the source address of the client (not {@code null})
     * @return the risk score ({@code float})
     */
    public float calculateRiskScore(string sourceAddress) {
        Socket socket=new Socket(serverAddress,port);
        
        OutStream output= socket.getOutputStream();
        DataOutputStream out = new DataOutputStream(output);
        out.writeUTF(sourceAddress);
        
        InputStream input = socket.getInputStream();
        DataInputStream in = new DataInputStream(input);
        String line = in.readUTF();  
        
        socket.close();  
        
        riskScore = Float.parseFloat(line);
        return riskScore;
    }

    /**
     * Decode the role set using the source IP address runtime attribute from the given authorization identity.
     *
     * @param authorizationIdentity the authorization identity (not {@code null})
     * @return the role set (must not be {@code null})
     */
    public Roles decodeRoles(AuthorizationIdentity authorizationIdentity) {
        Attributes runtimeAttributes = authorizationIdentity.getRuntimeAttributes();
        if (runtimeAttributes.containsKey(KEY_SOURCE_ADDRESS)) {
            String sourceAddress = runtimeAttributes.getFirst(KEY_SOURCE_ADDRESS);
            if (sourceAddress != null) {
                    if (calculateRiskScore(sourceAddress)<=50) {
                        return roles;
                    }
                }
        }
        return Roles.NONE;
    }
}
