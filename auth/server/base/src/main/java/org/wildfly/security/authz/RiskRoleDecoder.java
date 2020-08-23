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
import static org.wildfly.common.Assert.checkMinimumParameter;
import static org.wildfly.common.Assert.checkMaximumParameter;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.io.InputStream;

import java.net.Socket;


/**
 * A decoder to obtain role information using the source IP address runtime attribute from the identity,
 * by analysing the risk associated with it
 *
 * @author <a href="mailto:piyush.palta@outlook.com">Piyush Palta</a>
 */

public class RiskRoleDecoder implements RoleDecoder {

    private int riskScore;
    private int riskThreshold;
    private String riskAnalyzerAddress;
    private int riskAnalyzerPort;
    private Roles roles;

    /**
     * Construct a new instance.
     *
     * @param roles the roles to associate with the identity if the source IP address is within threshold risk
     * @param riskAnalyzerAddress the IP address of risk analyzer server
     * @param riskAnalyzerPort the port number of risk analyzer server, must be >=1 and <=65535
     */
    public RiskRoleDecoder(Roles roles, String riskAnalyzerAddress, int riskAnalyzerPort) {
        checkNotNullParam("roles", roles);
        checkMinimumParameter("riskAnalyzerPort",1,riskAnalyzerPort);
        checkMaximumParameter("riskAnalyzerPort",65535,riskAnalyzerPort);
        this.riskScore=0;
        this.roles = roles;
        this.riskAnalyzerAddress = riskAnalyzerAddress;
        this.riskAnalyzerPort= riskAnalyzerPort;
        this.riskThreshold=50;
    }

    /**
     * Construct a new instance.
     *
     * @param roles the roles to associate with the identity if the source IP address is within threshold risk
     * @param riskAnalyzerAddress the IP address of risk analyzer server
     * @param riskAnalyzerPort the port number of risk analyzer server, must be >=1 and <=65535
     * @param riskThreshold the threshold risk above which roles won't be assigned, must be within range 0 to 100
     */
    public RiskRoleDecoder(Roles roles, String riskAnalyzerAddress, int riskAnalyzerPort, int riskThreshold){
        checkNotNullParam("roles", roles);
        checkNotNullParam("riskAnalyzerAddress", riskAnalyzerAddress);
        checkMinimumParameter("riskAnalyzerPort",1,riskAnalyzerPort);
        checkMaximumParameter("riskAnalyzerPort",65535,riskAnalyzerPort);
        checkMinimumParameter("riskThreshold",0,riskThreshold);
        checkMaximumParameter("riskAnalyzerPort",100,riskThreshold);
        this.riskScore=0;
        this.roles = roles;
        this.riskAnalyzerAddress = riskAnalyzerAddress;
        this.riskAnalyzerPort=riskAnalyzerPort;
        this.riskThreshold=riskThreshold;
    }


    /**
     * Calculate Risk Score based on the source address to make authorization decision
     *
     * @param sourceAddress the source address of the client (not {@code null})
     * @return the risk score ({@code float})
     */
    private int calculateRiskScore(String sourceAddress) {
        try{
        Socket socket=new Socket(riskAnalyzerAddress,riskAnalyzerPort);

        OutputStream output= socket.getOutputStream();
        DataOutputStream out = new DataOutputStream(output);
        out.writeUTF(sourceAddress);

        InputStream input = socket.getInputStream();
        DataInputStream in = new DataInputStream(input);
        String line = in.readUTF();

        socket.close();
        riskScore = Integer.parseInt(line);
        }catch (Exception e){
            throw new RuntimeException(e);
        }
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
                    if (calculateRiskScore(sourceAddress)<=riskThreshold) {
                        return roles;
                    }
                }
        }
        return Roles.NONE;
    }
}

