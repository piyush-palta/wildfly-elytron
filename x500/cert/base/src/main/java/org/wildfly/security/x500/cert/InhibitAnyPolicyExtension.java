/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
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

package org.wildfly.security.x500.cert;

import org.wildfly.common.Assert;
import org.wildfly.security.asn1.ASN1Encoder;
import org.wildfly.security.x500.X500;

/**
 * The "inhibit anyPolicy" certificate extension as defined by <a href="https://tools.ietf.org/html/rfc5280#section-4.2.1.14">RFC 5280 § 4.2.1.14</a>.
 *
 * @author <a href="mailto:david.lloyd@redhat.com">David M. Lloyd</a>
 */
public final class InhibitAnyPolicyExtension extends X509CertificateExtension {
    private final int skipCerts;

    /**
     * Construct a new instance.
     *
     * @param skipCerts the number of additional non-self-issued certificates that may appear in the path before {@code anyPolicy} is no longer permitted (must be &gt;= 0)
     */
    public InhibitAnyPolicyExtension(final int skipCerts) {
        super(true);
        Assert.checkMinimumParameter("skipCerts", 0, skipCerts);
        this.skipCerts = skipCerts;
    }

    public String getId() {
        return X500.OID_CE_INHIBIT_ANY_POLICY;
    }

    public void encodeTo(final ASN1Encoder encoder) {
        encoder.encodeInteger(skipCerts);
    }
}
