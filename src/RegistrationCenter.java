import it.unisa.dia.gas.jpbc.Element;

import java.util.Arrays;
import java.util.List;

public class RegistrationCenter {

    public Element[] tvk;
    private Element[] tsk;
    private Element rtk;//the private key of trace key
    public Element rrk;//the trace key


    //可信方密钥生成算法
    public void TAKeyGen(RAAScheme param, int num) {

        Element[] tsk = new Element[num];
        Element[] tvk = new Element[num];

        //Generate the signature private key and the public key for the reg
        for (int i = 0; i < num; i++) {
            tsk[i] = param.pairing.getZr().newRandomElement().getImmutable();
            tvk[i] = param.g2.duplicate().powZn(tsk[i]).getImmutable();
        }

        Element rtk = param.pairing.getZr().newRandomElement().getImmutable();
        Element rrk = param.g1.duplicate().powZn(rtk).getImmutable();

        this.tvk = tvk;
        this.tsk = tsk;
        this.rtk = rtk;
        this.rrk = rrk;

        System.out.println();
        System.out.println("The public and private keys for the registry are being generated.............");
        for (int i = 0; i < tsk.length; i++) {
            System.out.println("signing private key tsk[" + i + "] = " + tsk[i]);
            System.out.println("verification key tvk[" + i + "] = " + tvk[i]);
        }
        System.out.println("The registry's tracking private key rtk = " + rtk);
        System.out.println("The registry's tracking public key rrk = " + rrk);

    }

    //SP
    public Element[] SPKeyGen(RAAScheme param) {
        Element psk = param.pairing.getZr().newRandomElement().getImmutable();
        Element pvk = param.g2.duplicate().powZn(psk).getImmutable();

        Element[] sp = new Element[2];
        sp[0] = psk;
        sp[1] = pvk;

        return sp;

    }




    public TToken TokenIssue(RAAScheme param, Element[] proofs, Vehicle vehicle, RegistrationCenter ta, String[] path) {

        Element[] proof = proofs;

        Element Rl = param.g1.duplicate().powZn(proof[0]).getImmutable();//g1^sa
        Element Rr = vehicle.uvk.duplicate().powZn(proof[1]).negate();

        Element RR = Rl.duplicate().mul(Rr).getImmutable();
        System.out.print("RR = ");
        System.out.println(RR);

        //Element conn = RR.duplicate().add(user.uvk);

        byte[] conn1 = ta.tvk[0].toBytes();
        byte[] conn2 = vehicle.uvk.toBytes();
        byte[] conn3 = RR.toBytes();
        byte[] connt = new byte[conn1.length + conn2.length + conn3.length];
        System.arraycopy(conn1, 0, connt, 0, conn1.length);
        System.arraycopy(conn2, 0, connt, conn1.length, conn2.length);
        System.arraycopy(conn3, 0, connt, conn2.length, conn3.length);

        //Element cc = pairing.getZr().newElementFromHash(conn.toBytes(), 0, conn.getLengthInBytes());
        Element cc = param.pairing.getZr().newElementFromHash(connt, 0, connt.length);

        System.out.print("cc = ");
        System.out.println(cc);

        Element[] tToken = new Element[path.length];
        Element[] eta = new Element[path.length];

        if (cc.isEqual(proof[1])) {
            System.out.println("verify successfully.........");
            System.out.println("RC is generating acc token.........");


            Element[] upath = Util.StringToElementOne(param.pairing, path);
            Element[] exp = new Element[upath.length];
            Element[] iexp = new Element[upath.length];
            Element[] base1 = new Element[upath.length];
            Element[] base = new Element[upath.length];


            for (int i = 0; i < path.length; i++) {

                eta[i] = param.pairing.getZr().newRandomElement().getImmutable();//eta
                exp[i] = tsk[0].add(eta[i]).getImmutable();//tsk1+eta_i
                iexp[i] = exp[i].duplicate().invert().getImmutable();//逆元
                base1[i] = param.g__1.duplicate().powZn(upath[i]).duplicate().mul(vehicle.uvk).getImmutable();//g__1^n_i*upk
                base[i] = param.g_1.duplicate().mul(base1[i]).getImmutable();//
                tToken[i] = base[i].duplicate().powZn(iexp[i]).getImmutable();//tk_u^acc

                System.out.println("f[" + i + "] = " + eta[i]);
                System.out.println("tToken[" + i + "] = " + tToken[i]);

            }
        } else {
            System.out.println("The proof of usk is wrong.");
        }

        TToken ttoken = new TToken();
        ttoken.tToken = tToken;
        ttoken.eta = eta;

        return ttoken;

    }



    public String[] Userpath(CBTree cbt) {
        String[] st = new String[3];
        return st;

    }


    public String[] RCnode(CBTree cbt) {
        String[] RC = new String[3];
        return RC;
    }


    public RToken Revoke(RAAScheme param, String[] sr, String t) {
        Element[] stn = Util.StringToElementOne(param.pairing, sr);
        Element tt = Util.StringToElement(param.pairing, t);

        Element[] rtoken = new Element[sr.length];
        Element[] exp1 = new Element[sr.length];
        Element[] exp2 = new Element[sr.length];
        Element[] exp = new Element[sr.length];

        for (int i = 0; i < sr.length; i++) {

            exp1[i] = tsk[1].duplicate().mul(stn[i]).getImmutable();//tsk2*n
            exp2[i] = tsk[2].duplicate().mul(tt).getImmutable();//tsk3*t
            exp[i] = tsk[0].duplicate().add(exp1[i]).add(exp2[i]).getImmutable();
            rtoken[i] = param.g1.duplicate().powZn(exp[i]).getImmutable();

        }

        RToken rt = new RToken();
        rt.rToken = rtoken;

        return rt;

    }

    public Element Update(RAAScheme param, String[] sr, String[] upath, Tranv tranv, RToken rToken, Element[] list) {
        Element upk = tranv.upk;
        List<Element> elelist = Arrays.asList(list);
        boolean result = elelist.contains(upk);
        String node = null;
        if (!result) {

            for (int i = 0; i < upath.length; i++) {
                for (int j = 0; j < sr.length; j++) {
                    if (upath[i] == sr[j]) {
                        node = upath[i];
                    }
                }
            }
            System.out.println("node = " + node);

            if(rToken.rToken.length == 1){
                System.out.println("[" + node + "] Corresponding rToken = " + rToken.rToken[0]);
                return rToken.rToken[0];
            }
            else {
                System.out.println("[" + node + "] Corresponding rToken = " + rToken.rToken[1]);
                return rToken.rToken[1];
            }


        } else {
            String res = "error";
            Element results = Util.StringToElement(param.pairing, res);
            return results;
        }

    }


    public Element Trace(ShowCred proof, Tranv tranv) {

        Element trace_token = proof.phi_1.duplicate().div(proof.phi_3.duplicate().powZn(rtk)).getImmutable();
        System.out.println("phi_1 = " + proof.phi_1);
        System.out.println("tToken = " + trace_token);

        if (trace_token.isEqual(tranv.tToken[0])) {
            System.out.println("Traced to vehicle OBU " + tranv.uid + ".");
        }

        return trace_token;

    }


}
