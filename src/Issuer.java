import it.unisa.dia.gas.jpbc.Element;
import lombok.Data;

import java.util.Arrays;
import java.util.List;
@Data
public class Issuer {
    private Element[] isk;
    public Element ivk_X;
    public Element[] ivk_Y;
    public Element[] ivk__Y;
    public Element[][] ivk_Z;
    public String ID;

    public Element[] attriss;






    public void IKeyGen(RAAScheme param, String identity, int n) {

        String ID = identity;

        Element[] sk = new Element[n];
        Element[] vk_Y = new Element[n];
        Element[] vk__Y = new Element[n];
        Element[][] vk_Z = new Element[n][n];

        for (int i = 0; i < n; i++) {

            sk[i] = param.pairing.getZr().newRandomElement().getImmutable();
        }
        for (int i = 1; i < n; i++) {//vk_Y1=Y0
            vk_Y[i] = param.g2.duplicate().powZn(sk[i]).getImmutable();
            vk__Y[i] = param.g1.duplicate().powZn(sk[i]).getImmutable();
            for(int j = 1; j < n; j++) {//vk_Z[1][2]=Z_0,1
                if(j != i)
                vk_Z[i][j]= param.g2.duplicate().powZn(sk[i].mul(sk[j])).getImmutable();
            }
        }
        Element  vk_X = param.g2.duplicate().powZn(sk[0]).getImmutable();
        this.isk = sk;
        this.ivk_X = vk_X;
        this.ivk_Y = vk_Y;
        this.ivk__Y = vk__Y;
        this.ivk_Z = vk_Z;
        this.ID = ID;

        System.out.println("the key pair of " + ID);
        for (int i = 0; i < isk.length; i++) {
            System.out.println("isk[" + i + "] = " + isk[i]);
        }
        for (int i = 1; i < ivk_Y.length; i++) {
            System.out.println("ivk_Y[" + i + "] = " + ivk_Y[i]);}
        for (int i = 1; i < ivk__Y.length; i++) {
            System.out.println("ivk__Y[" + i + "] = " + ivk__Y[i]);}
        for (int i = 1; i < ivk_Z.length; i++) {
            for(int j = 1; j < n ; j++) {
                if(j != i)
                    System.out.println("ivk_Z[" + i + "] "+"["+j+"] = " + ivk_Z[i][j]);
            }

        }
        System.out.println("ivk_X = " + ivk_X);
        System.out.println();

    }



    public Element CredIssue(RAAScheme param, Element[] proofs, Vehicle vehicle, Issuer issuer, String[] attr, Element[] list) {
        Element upk = vehicle.uvk;
        List<Element> elelist = Arrays.asList(list);
        boolean result = elelist.contains(upk);
        if (!result) {
            System.out.println("non-revoked");
            System.out.println("verifying......");

            Element[] proof = proofs;

            //将Element[]数组元素转成数组元素不可变的list数组形式
            //for example: Element[0] = 0, Element[1] = 1; list = [0,1]
            //List prr = Arrays.stream(proof).toList();
            //List list = Collections.unmodifiableList(prr);
            //System.out.println(list.get(1));//相当于输出Element[1]

            Element Rl = param.g1.duplicate().powZn(proof[0]).getImmutable();
            Element Rr = vehicle.uvk.duplicate().powZn(proof[1]).negate();

            Element RR = Rl.duplicate().mul(Rr).getImmutable();
            System.out.print("RR = ");
            System.out.println(RR);

            //Element conn = RR.duplicate().add(user.uvk);

            byte[] conn1 = issuer.ivk_Y[1].toBytes();
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

            Element exp = null;

            if (cc.isEqual(proof[1])) {
                System.out.println("successful");
                System.out.println("signing..........");
                Element[] attribute = new Element[attr.length];
                Element[] ya = new Element[attr.length];

                for (int i = 1; i < attr.length; i++) {
                    byte[] att = attr[i].getBytes();
                    attribute[i] = param.pairing.getZr().newElementFromBytes(att, 0);
                    ya[i] = issuer.isk[i+1].duplicate().mul(attribute[i]).getImmutable();//y_k,i*attr

                }
                this.attriss= attribute;

                Element expp = ya[1];
                for (int i = 2; i < attr.length; i++) {//expp=SUM y·attr
                    expp = expp.duplicate().add(ya[i]).getImmutable();

                }

                exp = issuer.isk[0].duplicate().add(expp).getImmutable();//exp= x+SUM y·attr




            } else {
                System.out.println("The proof of usk is wrong.");
            }


            return exp;


        } else {
            String res = "error!";
            Element results = Util.StringToElement(param.pairing, res);
            return results;
        }




    }
    public Element[] SeqSig(RAAScheme param,Vehicle vehicle, Issuer issuer,  Element sigma1_k , Element sigma2_k , Element phi_0 ,Element exp){

        Element upk = vehicle.uvk;
        Element r_k = param.pairing.getZr().newRandomElement().getImmutable();
        Element phi = phi_0.duplicate().powZn(r_k).getImmutable();
        Element sigma_k1 = sigma1_k.duplicate().powZn(r_k).getImmutable();//g_1^r
        Element sigma_k2 = sigma2_k.duplicate().powZn(r_k).mul(sigma1_k.powZn(r_k.mul(exp))).mul(phi_0.powZn(r_k.mul(issuer.isk[1]))).getImmutable();
        Element[] cred = {sigma_k1,sigma_k2,phi};
        System.out.print("issuer" + issuer.ID + "issued cred " + "=" + sigma_k1+","+sigma_k2);
        return cred;
    }
}
