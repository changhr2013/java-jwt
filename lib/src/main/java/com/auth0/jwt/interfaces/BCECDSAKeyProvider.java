package com.auth0.jwt.interfaces;

import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;

/**
 * Bouncy Castle Elliptic Curve (EC) Public/Private Key provider.
 *
 * @author changhr
 * @create 2019-05-13 19:10
 */
public interface BCECDSAKeyProvider extends KeyProvider<BCECPublicKey, BCECPrivateKey> {

}
