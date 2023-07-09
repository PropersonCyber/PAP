import it.unisa.dia.gas.jpbc.Element;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class ServiceProvider {

    private Element psk;
    public Element pvk;

    //将TA生成的密钥对作为服务提供商的公私钥
    public void KeySet(RAAScheme param, Element[] keypair) {
        this.psk = keypair[0];
        this.pvk = keypair[1];

        System.out.println();
        System.out.println("the psk of the service provider = " + psk);
        System.out.println("the pvk of the service provider = " + pvk);
    }

    public Element[] PreCompute(RAAScheme param, RegistrationCenter ta, String t) {
        Element D1_p2 = param.pairing.pairing(param.g__1, param.g2).getImmutable();//(g__1,g2)
        Element D1_p3 = param.pairing.pairing(param.g1, param.g2).getImmutable();//(g1,g2)
        Element D1_p4 = param.pairing.pairing(ta.rrk, ta.tvk[0]).getImmutable();//(apk,pk_1)
        Element D1_p5 = param.pairing.pairing(ta.rrk, param.g2).getImmutable();//(apk,g2)
        Element D1_p6 = param.pairing.pairing(param.g_1, param.g2).getImmutable();//(g_1,g2)

        Element epoch_t = Util.StringToElement(param.pairing, t).getImmutable();
        Element D2_p1 = param.pairing.pairing(param.g1, ta.tvk[1]).getImmutable();//(g1,pk_2)
        Element D2_p2 = D1_p3.getImmutable();//(g1,g2)
        Element D2_p3 = param.pairing.pairing(param.g1, ta.tvk[0].duplicate().mul(ta.tvk[2].powZn(epoch_t))).getImmutable();//分母

        Element[] precom = {D1_p2, D1_p3, D1_p4, D1_p5, D1_p6, D2_p1, D2_p2, D2_p3};
        return precom;

    }

    public void Verify(RAAScheme param, RegistrationCenter ta, ShowCred proof, Issuer[] issuer, String t, Element[] access_policy, String mes) {

        Credential credential=new Credential(param.pairing.getG2().newOneElement().getImmutable(),param.pairing.getG1().newOneElement().getImmutable());
        System.out.println(credential);
        //计算D_1
        Element[] prevalue = PreCompute(param, ta, t);
        Element D1_r1 = param.pairing.pairing(proof.phi_1.duplicate().powZn(proof.W_eta).negate(), param.g2).getImmutable();
        Element D1_r2 = prevalue[0].duplicate().powZn(proof.W_n).getImmutable();
        Element D1_r3 = prevalue[1].duplicate().powZn(proof.W_z).getImmutable();
        Element D1_r4 = prevalue[2].duplicate().powZn(proof.W_o).getImmutable();
        Element D1_r5 = prevalue[3].duplicate().powZn(proof.W_beta).getImmutable();
        Element D1_r6_1 = param.pairing.pairing(proof.phi_1, ta.tvk[0]).getImmutable();
        Element D1_r6_2 = prevalue[4].getImmutable();
        Element D1_r6 = D1_r6_1.duplicate().div(D1_r6_2).powZn(proof.c_auth).negate().getImmutable();
        Element D_1 = D1_r1.duplicate().mul(D1_r2).mul(D1_r3).mul(D1_r4).mul(D1_r5).mul(D1_r6).getImmutable();

        //计算D_2
        Element D2_r1 = prevalue[5].duplicate().powZn(proof.W_n).getImmutable();
        Element D2_r2 = prevalue[6].duplicate().powZn(proof.W_e).getImmutable();
        Element D2_r3_1 = param.pairing.pairing(proof.phi_2, param.g2).getImmutable();
        Element D2_r3_2 = prevalue[7].getImmutable();
        Element D2_r3 = D2_r3_1.duplicate().div(D2_r3_2).powZn(proof.c_auth).negate().getImmutable();
        Element D_2 = D2_r1.duplicate().mul(D2_r2).mul(D2_r3).getImmutable();

        //计算D_3
        Element D3_r1 = param.g1.duplicate().powZn(proof.W_o).getImmutable();
        Element D3_r2 = proof.phi_3.duplicate().powZn(proof.c_auth).negate().getImmutable();
        Element D_3 = D3_r1.duplicate().mul(D3_r2).getImmutable();

        //计算phi_5
        Element phi_5_r1= proof.B.duplicate().powZn(proof.W_z).getImmutable();
        Element phi_5_r2= proof.phi_4.duplicate().powZn(proof.c_auth).negate().getImmutable();
        Element phi_5 = phi_5_r1.duplicate().mul(phi_5_r2).getImmutable();

        //将消息转成byte数组元素
        Element mess = Util.StringToElement(param.pairing, mes);

        //计算cc
        byte[] b_phi_1 = proof.phi_1.toBytes();
        byte[] b_phi_2 = proof.phi_2.toBytes();
        byte[] b_phi_3 = proof.phi_3.toBytes();
        byte[] b_phi_4 = proof.phi_4.toBytes();
        byte[] b_phi_5 = phi_5.toBytes();
        byte[] b_D_1 = D_1.toBytes();
        byte[] b_D_2 = D_2.toBytes();
        byte[] b_D_3 = D_3.toBytes();
        byte[] b_mess = mess.toBytes();


        byte[] bytes = new byte[b_phi_1.length + b_phi_2.length + b_phi_3.length + b_phi_4.length + b_phi_5.length+ b_D_1.length + b_D_2.length + b_D_3.length  + b_mess.length];
        System.arraycopy(b_phi_1, 0, bytes, 0, b_phi_1.length);
        System.arraycopy(b_phi_2, 0, bytes, b_phi_1.length, b_phi_2.length);
        System.arraycopy(b_phi_3, 0, bytes, b_phi_2.length, b_phi_3.length);
        System.arraycopy(b_phi_4, 0, bytes, b_phi_3.length, b_phi_4.length);
        System.arraycopy(b_phi_5, 0, bytes, b_phi_4.length, b_phi_5.length);
        System.arraycopy(b_D_1, 0, bytes, b_phi_5.length, b_D_1.length);
        System.arraycopy(b_D_2, 0, bytes, b_D_1.length, b_D_2.length);
        System.arraycopy(b_D_3, 0, bytes, b_D_2.length, b_D_3.length);
        System.arraycopy(b_mess, 0, bytes, b_D_3.length, b_mess.length);

        Element cc = param.pairing.getZr().newElementFromHash(bytes, 0, bytes.length);




        System.out.println(credential.mulIssuerIvk);
        System.out.println(credential.mulIssuerIvkx);
        System.out.println(param.pairing.getG2().newOneElement());
        for (int k = 0; k < issuer.length; k++) {

            credential.mulIssuerIvkx = credential.mulIssuerIvkx.duplicate().mul(issuer[k].ivk_X).getImmutable();//mul X_k
            credential.mulIssuerIvk0 = credential.mulIssuerIvk0.duplicate().mul(issuer[k].ivk_Y[1].duplicate().powZn(proof.W_z).getImmutable()).getImmutable();//mulY_k,0^w_z
        }
        Element F_right = proof.aggsigma1.duplicate().mul(credential.mulIssuerIvkx).mul(proof.aggkmulY_ki).getImmutable();//sigma1~*mulX*Y^a
        Element F = param.pairing.pairing(proof.randomsig1, F_right);
        System.out.println("D_1 = " + D_1);
        System.out.println("D_2 = " + D_2);
        System.out.println("D_3 = " + D_3);
        System.out.println("F = " + F);
        System.out.println("cc = " + cc);

        //randomized sig
        Element  ransigpairing_l1= param.pairing.pairing(proof.randomsig1, credential.mulIssuerIvk0);

        Element ransigpairing_l= ransigpairing_l1.duplicate().div(proof.E).getImmutable();
        Element  ransigpairing_r1= param.pairing.pairing(proof.randomsig2, param.g2);
        Element ransigpairing_r2 = ransigpairing_r1.duplicate().div(F).getImmutable();
        Element ransigpairing_r= ransigpairing_r2.duplicate().powZn(cc).getImmutable();
        //redactable sig
        Element[] Rsigpairingl=new Element[proof.Rsig1.length];
        Element[] Rsigpairingr=new Element[proof.Rsig2.length];
        for (int k = 0; k < issuer.length; k++) {

                Rsigpairingl[k]=param.pairing.pairing(proof.Rsig1[k],proof.mulIssuerIvk__Y[k]);
                Rsigpairingr[k]=param.pairing.pairing(param.g1,proof.Rsig2[k]);
                if (Rsigpairingl[k].isEqual(Rsigpairingr[k])){
                    System.out.println("issuer"+ k +"The redactable signature verification succeeded");
                } else {
                    System.out.println("issuer"+ k +"The redactable signature verification failed");
                }
            }

        if (cc.isEqual(proof.c_auth)&&ransigpairing_l.isEqual(ransigpairing_r)) {
            System.out.println("Vehicle OBU verification succeeded");
        } else {
            System.out.println("Vehicle OBU verification failed");
        }


    }
}
