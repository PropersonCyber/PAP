import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

import javax.xml.ws.EndpointReference;
import java.util.*;
import java.util.stream.Collectors;

public class Vehicle {

    private Element usk;
    public Element uvk;
    public String id;

    public Element addr_upk;

    public Element addr_usk;


    public void UKeyGen(RAAScheme param, String identity) {

        String uid = identity;
        Element sk = param.pairing.getZr().newRandomElement().getImmutable();
        Element pk = param.g1.duplicate().powZn(sk).getImmutable();
        Element addr_usk = param.pairing.getZr().newRandomElement().getImmutable();
        Element addr_upk = param.g1.duplicate().powZn(addr_usk).getImmutable();

        this.usk = sk;
        this.uvk = pk;
        this.id = uid;
        this.addr_usk = addr_usk;
        this.addr_upk = addr_upk;

        System.out.println("EV OBU " + id + " usk = " + usk);
        System.out.println("EV OBU " + id + " uvk = " + uvk);
        System.out.println("EV OBU " + id + " addr_usk = " + addr_usk);
        System.out.println("EV OBU " + id + " addr_upk = " + addr_upk);
    }



    public Element[] TokenObtain(RAAScheme param, Vehicle vehicle, RegistrationCenter ta) {

        Element r_a = param.pairing.getZr().newRandomElement().getImmutable();
        Element R = param.g1.duplicate().powZn(r_a).getImmutable();

        byte[] con1 = ta.tvk[0].toBytes();
        byte[] con2 = vehicle.uvk.toBytes();
        byte[] con3 = R.toBytes();
        byte[] cont = new byte[con1.length + con2.length + con3.length];
        System.arraycopy(con1, 0, cont, 0, con1.length);
        System.arraycopy(con2, 0, cont, con1.length, con2.length);
        System.arraycopy(con3, 0, cont, con2.length, con3.length);

        Element c = param.pairing.getZr().newElementFromHash(cont, 0, cont.length);

        System.out.print("c = ");
        System.out.println(c);


        Element s_a = r_a.duplicate().add(c.duplicate().mul(vehicle.usk)).getImmutable();
        System.out.println("s_a = " + s_a);


        Element[] result = new Element[3];
        result[0] = s_a;
        result[1] = c;
        result[2] = R;

        return result;

    }

    public void TTokenVerify(RAAScheme param, RegistrationCenter ta, TToken ttoken, Vehicle vehicle, String[] path) {

        Element[] node = Util.StringToElementOne(param.pairing, path);//upath
        Element[] left1 = new Element[path.length];
        Element[] left = new Element[path.length];
        Element[] base1 = new Element[path.length];
        Element[] base = new Element[path.length];
        Element[] right = new Element[path.length];
        long start_token = System.currentTimeMillis();
        for (int i = 0; i < path.length; i++) {
            left1[i] = ta.tvk[0].duplicate().mul(param.g2.powZn(ttoken.eta[i])).getImmutable();//tvk1*g2^etai
            left[i] = param.pairing.pairing(ttoken.tToken[i], left1[i]).getImmutable();//
            base1[i] = param.g__1.duplicate().powZn(node[i]).duplicate().mul(vehicle.uvk).getImmutable();
            base[i] = param.g_1.duplicate().mul(base1[i]).getImmutable();
            right[i] = param.pairing.pairing(base[i], param.g2).getImmutable();
            if (left[i].isEqual(right[i])) {
                System.out.println("left[" + i + "] = " + left[i]);
                System.out.println("right[" + i + "] = " + right[i]);
                System.out.println("tToken[" + i + "]" + "successed！");
            } else {
                System.out.println("tToken[" + i + "] " + "error！");
            }
        }

        long end_token = System.currentTimeMillis();
        //System.out.println("time in the ttoken algorithm " + (end_token - start_token) + "ms");


    }



    public void RTokenVerify(RAAScheme param, RegistrationCenter ta, Element rToken, String subnode, String t) {

        Element node = Util.StringToElement(param.pairing, subnode);//root
        Element epoch = Util.StringToElement(param.pairing, t);

        long start_revoke = System.currentTimeMillis();

        Element left = param.pairing.pairing(rToken, param.g2).getImmutable();

        Element r1 = ta.tvk[1].duplicate().powZn(node).getImmutable();//tvk2^n
        Element r2 = ta.tvk[2].duplicate().powZn(epoch).getImmutable();//tvk3^t
        Element r3 = ta.tvk[0].duplicate().mul(r1).mul(r2).getImmutable();

        Element right = param.pairing.pairing(param.g1, r3).getImmutable();

        if (left.isEqual(right)) {
            System.out.println("left = " + left);
            System.out.println("right = " + right);
            System.out.println(" the verification of rToken successed");
        } else {
            System.out.println("rToken 错误.");
        }
        long end_revoke = System.currentTimeMillis();
        System.out.println("time of verifying the revocation token in user class = " + (end_revoke - start_revoke) + "ms");


    }



    public Element[] CredObtain(RAAScheme param, Vehicle vehicle, Issuer issuer, String[] attr) {

        Element f = param.pairing.getZr().newRandomElement().getImmutable();
        Element R = param.g1.duplicate().powZn(f).getImmutable();


        byte[] con1 = issuer.ivk_Y[1].toBytes();
        byte[] con2 = vehicle.uvk.toBytes();
        byte[] con3 = R.toBytes();
        byte[] cont = new byte[con1.length + con2.length + con3.length];
        System.arraycopy(con1, 0, cont, 0, con1.length);
        System.arraycopy(con2, 0, cont, con1.length, con2.length);
        System.arraycopy(con3, 0, cont, con2.length, con3.length);


        Element c = param.pairing.getZr().newElementFromHash(cont, 0, cont.length);

        System.out.print("c = ");
        System.out.println(c);

        Element ff = c.duplicate().mul(vehicle.usk);
        Element k = f.add(ff).getImmutable();
        System.out.println("k = " + k);


        Element[] result = new Element[2];
        result[0] = k;
        result[1] = c;

        return result;


    }


    //单个凭证验证算法
    public int CredVerify(RAAScheme param, Element[] sig, Vehicle vehicle, Issuer[] issuer) {

        Credential credential=new Credential(param.pairing.getG2().newOneElement().getImmutable(),param.pairing.getG1().newOneElement().getImmutable());
        System.out.println(credential);

        Element left = param.pairing.pairing(sig[1], param.g2);
        int MaxSizeofissatt = 0;
        List<List<Element>> ListArr = new ArrayList<>();//all issuers' attribute set
        for (int k = 0; k < issuer.length; k++) {

            List<Element> isslist = Arrays.asList(issuer[k].attriss);
            if (isslist.size() > MaxSizeofissatt)
                MaxSizeofissatt = isslist.size();
            ListArr.add(isslist);
        }
        Element[][] exp1 = new Element[issuer.length][MaxSizeofissatt];
        Element[] exp2 = new Element[MaxSizeofissatt];
        Element[] mulatt = new Element[MaxSizeofissatt];
        for (int k = 0; k < issuer.length; k++) {
            mulatt[k] = param.pairing.getG2().newOneElement().getImmutable();
        }

        for (int k = 0; k < issuer.length; k++) {
            for (int i = 1; i < MaxSizeofissatt; i++) {
                exp1[k][i] = issuer[k].ivk_Y[i + 1].duplicate().powZn(ListArr.get(k).get(i)).getImmutable();//each issuer Y_k,i^attr_k,i
                mulatt[k] = mulatt[k].duplicate().mul(exp1[k][i]);
            }
            exp2[k] = issuer[k].ivk_Y[1].duplicate().powZn(vehicle.usk).getImmutable();//each Y_k,0^usk
            credential.mulIssuerIvk0 = credential.mulIssuerIvk0.duplicate().mul(exp2[k]).getImmutable();//mul Y_k,0^usk
            credential.mulIssuerIvk = credential.mulIssuerIvk.duplicate().mul(mulatt[k]).getImmutable();//mul Y_k,i^attr
            credential.mulIssuerIvkx = credential.mulIssuerIvkx.duplicate().mul(issuer[k].ivk_X).getImmutable();//mul X_k
        }

        Element rsig = credential.mulIssuerIvkx.duplicate().mul(credential.mulIssuerIvk).mul(credential.mulIssuerIvk0).getImmutable();//mul Y_k,0^usk·Y_k,i^attr·X_k
        Element right = param.pairing.pairing(sig[0], rsig);

        if (left.isEqual(right)) {
            System.out.println("left = " + left);
            System.out.println("right = " + right);
            System.out.println("Access credential cred verification succeeded");
        } else {
            System.out.println("The verification of single credential is wrong.");
        }

        return 0;
    }




    public Element[] PreCompute(RAAScheme param, RegistrationCenter ta) {
        Element D1_p2 = param.pairing.pairing(param.g__1, param.g2).getImmutable();
        Element D1_p3 = param.pairing.pairing(param.g1, param.g2).getImmutable();
        Element D1_p4 = param.pairing.pairing(ta.rrk, ta.tvk[0]).getImmutable();
        Element D1_p5 = param.pairing.pairing(ta.rrk, param.g2).getImmutable();

        Element D2_p1 = param.pairing.pairing(param.g1, ta.tvk[1]).getImmutable();
        Element D2_p2 = D1_p3.getImmutable();

        Element[] preCom = new Element[6];
        preCom[0] = D1_p2.getImmutable();
        preCom[1] = D1_p3.getImmutable();
        preCom[2] = D1_p4.getImmutable();
        preCom[3] = D1_p5.getImmutable();
        preCom[4] = D2_p1.getImmutable();
        preCom[5] = D2_p2.getImmutable();

        return preCom;
    }


    public Element[] InterSet(RAAScheme param, Element[] array1, Element[] array2) {
        Element[] result;
        int MAX_LENGTH = array2.length;
        int MIN_LENGTH = array1.length;
        ;
        if (array1.length > array2.length) {
            MAX_LENGTH = array1.length;
            MIN_LENGTH = array2.length;
        }
        result = new Element[MAX_LENGTH];



        for (int i = 1; i < MAX_LENGTH; i++) {
            for (int j = 1; j < MIN_LENGTH; j++) {
                if (array1[i].isEqual(array2[j])) {
                    result[i] = array1[i];
                    break;
                }
                result[i] = param.pairing.getG2().newOneElement();

            }
        }

        return result;
    }


    public Element[] CompSet(RAAScheme param, Element[] array1, Element[] array2) {
        Element[] result;

        int MAX_LENGTH = array1.length;
        int MIN_LENGTH = array2.length;
        if (array1.length < array2.length) {
            MAX_LENGTH = array2.length;
            MIN_LENGTH = array1.length;
        }
        result = new Element[MAX_LENGTH];



        for (int i = 1; i < MAX_LENGTH; i++) {
            boolean isNotEqual = false;
            for (int j = 1; j < MIN_LENGTH; j++) {
                // isNotEqual=false;
                if (!array1[i].isEqual(array2[j])) {
                    isNotEqual = true;
                    continue;
                }
                isNotEqual = false;
                result[i] = param.pairing.getG2().newOneElement();
                break;
            }
            if (isNotEqual)
                result[i] = array1[i];
        }

        return result;
    }


    public ShowCred Auth(RAAScheme param, Element[] sig, Element[] access_policy, String ID_CS, RegistrationCenter ta, Issuer[] issuer, Vehicle vehicle, Element ttoken, Element eta, Element rtoken, String node, String mes) {
        long start1 = System.currentTimeMillis();

        //random
        Element sk_ots1 = param.pairing.getZr().newRandomElement().getImmutable();
        Element sk_ots2 = param.pairing.getZr().newRandomElement().getImmutable();
        Element vk_ots1 = param.g1.duplicate().powZn(sk_ots1).getImmutable();
        Element vk_ots2 = param.g1.duplicate().powZn(sk_ots2).getImmutable();
        Element r_e = param.pairing.getZr().newRandomElement().getImmutable();
        Element r_v = param.pairing.getZr().newRandomElement().getImmutable();
        Element S_e = param.pairing.getZr().newRandomElement().getImmutable();
        Element S_z = param.pairing.getZr().newRandomElement().getImmutable();
        Element S_eta = param.pairing.getZr().newRandomElement().getImmutable();
        Element S_o = param.pairing.getZr().newRandomElement().getImmutable();
        Element S_n = param.pairing.getZr().newRandomElement().getImmutable();
        Element S_beta = param.pairing.getZr().newRandomElement().getImmutable();
        //Element sk_ots2 = param.pairing.getZr().newRandomElement().getImmutable();

        //compute phi
        Element phi_1 = ttoken.duplicate().mul(ta.rrk.duplicate().powZn(sk_ots1)).getImmutable();//ttok·rrk^r_o
        Element phi_2 = rtoken.duplicate().mul(param.g1.duplicate().powZn(r_e)).getImmutable();
        Element phi_3 = param.g1.duplicate().powZn(sk_ots1).getImmutable();
        Element IDCS = Util.StringToElement(param.pairing, ID_CS);
        byte[] contIDCS = IDCS.toBytes();
        Element B = param.pairing.getG1().newElementFromHash(contIDCS, 0, contIDCS.length);
        Element phi_4 = B.duplicate().powZn(vehicle.usk).getImmutable();
        Element phi_5 = B.duplicate().powZn(S_z).getImmutable();
        Element beta = sk_ots1.duplicate().mul(eta).getImmutable();//f,\eta
        long end1 = System.currentTimeMillis();

        //pre-com
        Element[] preValue = vehicle.PreCompute(param, ta);
        long start2 = System.currentTimeMillis();
        //D1
        Element D1_r1 = param.pairing.pairing(phi_1.duplicate().powZn(S_eta).negate(), param.g2).getImmutable();
        Element D1_r2 = preValue[0].duplicate().powZn(S_n).getImmutable();
        Element D1_r3 = preValue[1].duplicate().powZn(S_z).getImmutable();
        Element D1_r4 = preValue[2].duplicate().powZn(S_o).getImmutable();
        Element D1_r5 = preValue[3].duplicate().powZn(S_beta).getImmutable();
        Element D1 = D1_r1.duplicate().mul(D1_r2).mul(D1_r3).mul(D1_r4).mul(D1_r5).getImmutable();

        //D2
        Element D2_r1 = preValue[4].duplicate().powZn(S_n).getImmutable();
        Element D2_r2 = preValue[5].duplicate().powZn(S_e).getImmutable();
        Element D2 = D2_r1.duplicate().mul(D2_r2).getImmutable();

        //D3
        Element D3 = param.g1.duplicate().powZn(S_o).getImmutable();
        long end2 = System.currentTimeMillis();

        Element mess = Util.StringToElement(param.pairing, mes);

        //c
        byte[] b_phi_1 = phi_1.toBytes();
        byte[] b_phi_2 = phi_2.toBytes();
        byte[] b_phi_3 = phi_3.toBytes();
        byte[] b_phi_4 = phi_4.toBytes();
        byte[] b_phi_5 = phi_5.toBytes();
        byte[] b_D1 = D1.toBytes();
        byte[] b_D2 = D2.toBytes();
        byte[] b_D3 = D3.toBytes();
        byte[] b_mess = mess.toBytes();

        byte[] bytes = new byte[b_phi_1.length + b_phi_2.length + b_phi_3.length + b_phi_4.length + b_phi_5.length + b_D1.length + b_D2.length + b_D3.length + b_mess.length];
        System.arraycopy(b_phi_1, 0, bytes, 0, b_phi_1.length);
        System.arraycopy(b_phi_2, 0, bytes, b_phi_1.length, b_phi_2.length);
        System.arraycopy(b_phi_3, 0, bytes, b_phi_2.length, b_phi_3.length);
        System.arraycopy(b_phi_4, 0, bytes, b_phi_3.length, b_phi_4.length);
        System.arraycopy(b_phi_5, 0, bytes, b_phi_4.length, b_phi_5.length);
        System.arraycopy(b_D1, 0, bytes, b_phi_5.length, b_D1.length);
        System.arraycopy(b_D2, 0, bytes, b_D1.length, b_D2.length);
        System.arraycopy(b_D3, 0, bytes, b_D2.length, b_D3.length);
        System.arraycopy(b_mess, 0, bytes, b_D3.length, b_mess.length);

        long start3 = System.currentTimeMillis();
        Element c_auth = param.pairing.getZr().newElementFromHash(bytes, 0, bytes.length).getImmutable();

        Element n = Util.StringToElement(param.pairing, node);

        Element W_z = S_z.duplicate().add(c_auth.duplicate().mul(vehicle.usk)).getImmutable();
        Element W_eta = S_eta.duplicate().add(c_auth.duplicate().mul(eta)).getImmutable();
        Element W_n = S_n.duplicate().add(c_auth.duplicate().mul(n)).getImmutable();
        Element W_o = S_o.duplicate().add(c_auth.duplicate().mul(sk_ots1)).getImmutable();
        Element W_beta = S_beta.duplicate().add(c_auth.duplicate().mul(beta)).getImmutable();
        Element W_e = S_e.duplicate().add(c_auth.duplicate().mul(r_e)).getImmutable();
        long end3 = System.currentTimeMillis();


        long start4 = System.currentTimeMillis();


        Element[] Rsig1 = new Element[issuer.length];
        Element[] Rsig2 = new Element[issuer.length];
        Element[][] mulYki_rv = new Element[issuer.length][10];
        Element[] mulYk_rv = new Element[issuer.length];
        Element mulEY_k0 = param.pairing.getG2().newOneElement().getImmutable();
        Element aggkmulY_ki = param.pairing.getG2().newOneElement();
        Element CaggkmulY_ki = param.pairing.getG2().newOneElement();
        Element[][] mulZ_ki = new Element[issuer.length][10];
        Element[][] MULZ_k0 = new Element[issuer.length][10];
        Element[][] mulZfinal_ki = new Element[issuer.length][10];
        Element[] mulZ_k = new Element[issuer.length];
        Element[] MULYK_rv = new Element[issuer.length];
        Element[][] Inter_set = new Element[issuer.length][];
        Element[][] Comp_set = new Element[issuer.length][];
        Element One = param.pairing.getG2().newOneElement();

        for (int k = 0; k < issuer.length; k++) {

            Inter_set[k] = InterSet(param, issuer[k].attriss, access_policy);
            Comp_set[k] = CompSet(param, issuer[k].attriss, access_policy);
            for (int i = 1; i < Inter_set[k].length; i++) {
                System.out.println("Interset: " + " " + "issuer" + k + " " + Inter_set[k][i]);
                System.out.println("Compset: " + " " + "issuer" + k + " " + Comp_set[k][i]);
            }

        }


        Element[] aggjmulY_ki = new Element[access_policy.length];
        Element[] mulIssuerIvk__Y1 = new Element[issuer.length];
        Element[] mulIssuerIvk__Y= new Element[issuer.length];
        for (int k = 0; k < issuer.length; k++) {
            Element[][][] mulZ_kij = new Element[issuer.length][10][issuer[k].attriss.length];
            Element[][][] MULZ_k0j = new Element[issuer.length][10][issuer[k].attriss.length];
            mulZ_k[k] = param.pairing.getG2().newOneElement();
            mulYk_rv[k] = param.pairing.getG2().newOneElement().getImmutable();
            Element[][] mulY_ki = new Element[issuer.length][Comp_set[k].length];
            aggjmulY_ki[k] = param.pairing.getG2().newOneElement();
            mulIssuerIvk__Y1[k]=param.pairing.getG1().newOneElement();
            mulIssuerIvk__Y[k]=param.pairing.getG1().newOneElement();

            for (int i = 1; i < Inter_set[k].length; i++) {
                mulZ_ki[k][i] = param.pairing.getG2().newOneElement().getImmutable();
                MULZ_k0[k][i] = param.pairing.getG2().newOneElement().getImmutable();

                if (!Inter_set[k][i].isEqual(One)) {

                    mulYki_rv[k][i] = issuer[k].ivk_Y[i + 1].duplicate().powZn(r_v).getImmutable();

                    mulIssuerIvk__Y1[k] = mulIssuerIvk__Y1[k].duplicate().mul(issuer[k].ivk__Y[i+1]).getImmutable();

                    mulYk_rv[k] = mulYk_rv[k].duplicate().mul(mulYki_rv[k][i]).getImmutable();
                    for (int j = 1; j < Comp_set[k].length; j++) {

                        if (!Comp_set[k][j].isEqual(One)) {
                            mulZ_kij[k][i][j] = issuer[k].ivk_Z[i + 1][j + 1].duplicate().powZn(Comp_set[k][j]).getImmutable();
                            MULZ_k0j[k][i][j] = issuer[k].ivk_Z[1][j + 1].duplicate().powZn(Comp_set[k][j]).getImmutable();
                            MULZ_k0[k][i] = MULZ_k0[k][i].duplicate().mul(MULZ_k0j[k][i][j]).getImmutable();
                            mulZ_ki[k][i] = mulZ_ki[k][i].duplicate().mul(mulZ_kij[k][i][j]).getImmutable();
                            mulZfinal_ki[k][i] = MULZ_k0[k][i].duplicate().mul(mulZ_ki[k][i]).getImmutable();


                        }
                    }
                    mulZ_k[k] = mulZ_k[k].duplicate().mul(mulZfinal_ki[k][i]).getImmutable();//i次Z的聚合

                    //为CS聚合
                    mulY_ki[k][i] = issuer[k].ivk_Y[i + 1].duplicate().powZn(Inter_set[k][i]).getImmutable();//为CS计算访问策略的单个Y_ki^a_ki
                    aggjmulY_ki[k] = aggjmulY_ki[k].duplicate().mul(mulY_ki[k][i]).getImmutable();//CS符合访问策略的聚合i次

                }

            }
            MULYK_rv[k] = issuer[k].ivk_Y[1].duplicate().powZn(r_v).mul(mulYk_rv[k]).getImmutable();//连乘i次包括Yk0的Y_k,i^r_v
            Rsig2[k] = MULYK_rv[k].duplicate().mul(mulZ_k[k]).getImmutable();//sigma~_k,2
            System.out.println("Rsig2[k]:" + " " + "issuer" + k + " " + Rsig2[k]);
            aggkmulY_ki = aggkmulY_ki.duplicate().mul(aggjmulY_ki[k]).getImmutable();//CS的k次聚合
            mulIssuerIvk__Y[k]=  mulIssuerIvk__Y[k].duplicate().mul(issuer[k].ivk__Y[1].duplicate().mul(mulIssuerIvk__Y1[k]).getImmutable()).getImmutable();//乘上Y’_k,0



        }


//sigma1~
        for (int k = 0; k < issuer.length; k++) {

            Element[] CaggjmulY_kj = new Element[issuer.length];
            CaggjmulY_kj[k] = param.pairing.getG2().newOneElement();

            for (int j = 1; j < Comp_set[k].length; j++) {
                Element[][] CmulY_kj = new Element[issuer.length][Comp_set[k].length];
                if (!Comp_set[k][j].isEqual(One)) {
                    //补集相关
                    CmulY_kj[k][j] = issuer[k].ivk_Y[j + 1].duplicate().powZn(Comp_set[k][j]).getImmutable();//单个的sigma~Y_k,j^a_k,j
                    System.out.println("CmulY_kj:" + " " + k + " " + j + " " + CmulY_kj[k][j]);
                } else {
                    CmulY_kj[k][j] = param.pairing.getG2().newOneElement();
                    System.out.println("CmulY_kj:" + " " + k + " " + j + " " + CmulY_kj[k][j]);
                }
                //System.out.println("value " +k+j+ CmulY_kj[k][j]);
                CaggjmulY_kj[k] = CaggjmulY_kj[k].duplicate().mul(CmulY_kj[k][j]).getImmutable();//EV的j次聚合，sigma~k，1右側連乘


            }

            CaggkmulY_ki = CaggkmulY_ki.duplicate().mul(CaggjmulY_kj[k]).getImmutable();//EV的k次聚合

            Rsig1[k] = param.g2.duplicate().powZn(r_v).mul(CaggjmulY_kj[k]).getImmutable();//sigma~_k,1
            mulEY_k0 = mulEY_k0.duplicate().mul(issuer[k].ivk_Y[1].duplicate().powZn(S_z).getImmutable()).getImmutable();//Mul Y_k,0^sz
            //aggsigma1用于计算sigma~1，aggkmulY_ki用于为CS提供验证Fright相关的Y_k,i^a_k,i

        }

        Element aggsigma1 = param.g2.duplicate().powZn(r_v).mul(CaggkmulY_ki).getImmutable();//sigma~1
        Element randomsig1 = sig[0].duplicate().powZn(sk_ots1).getImmutable();//sigma1'
        Element randomsig2 = sig[1].duplicate().powZn(sk_ots1).mul(randomsig1.duplicate().powZn(r_v).getImmutable()).getImmutable();//sigma2'
        Element E = param.pairing.pairing(randomsig1, mulEY_k0);
        long end4 = System.currentTimeMillis();

//        int sizeOfAP= access_policy.length;
//
//        Element[][] R1Y_kj = new Element[issuer.length][MAX_ComSIZE];
//        Element[][] R2Y_kj = new Element[issuer.length][MAX_ComSIZE];
//
//        Element[] redSigma1_Y= new Element[issuer.length];
//        Element[] redSigma2_Y= new Element[issuer.length];
//        Element[] redSigma2_Z= new Element[issuer.length];
//
//        Element[] Rsig1= new Element[issuer.length];
//        Element[] Rsig2= new Element[issuer.length];
//        Element mulSigma1_Y=param.pairing.getG2().newOneElement().getImmutable();
//        Element mulEY_k0=param.pairing.getG2().newOneElement().getImmutable();
//
//
//        for (int k = 0; k < issuer.length; k++) {
//            redSigma1_Y[k]= param.pairing.getG2().newOneElement().getImmutable();
//            redSigma2_Y[k]= param.pairing.getG2().newOneElement().getImmutable();
//            redSigma2_Z[k]= param.pairing.getG2().newOneElement().getImmutable();
//
//        }
//
//        for (int k =  0; k < issuer.length; k++) {
//                for (int i = 1; i < sizeOfAP; i++) {
//                        R2Y_kj[k][i] = issuer[k].ivk_Y[i].duplicate().powZn(r_v).getImmutable();//each Y_k,j^r_v
//                        redSigma2_Y[k]= redSigma2_Y[k].duplicate().mul(R2Y_kj[k][i]).getImmutable();//连乘Y_k,j^r_v
//                        for (int j = 1; j< MAX_ComSIZE ; j++) {
//        //                    System.out.println("ComListArr " +k+" "+j+" "+ ComListArr.get(k).get(j));
//                                if(i!=j+1){
//                                    R3Y_kj[k][i][j] = issuer[k].ivk_Z[i][j+1].duplicate().powZn(ComListArr.get(k).get(j)).getImmutable();//each Z_k,j^a_k,j
//                                    redSigma2_Z[k] = redSigma2_Z[k].duplicate().mul(R3Y_kj[k][i][j]).getImmutable();//j连乘Z_k,j^a_k,j                                                                n
//                                }
//                        }
//                }
//        }
//
////        for(int k=0;k< issuer.length;k++){
////            for(int j=1;j<MAX_ComSIZE;j++){
////                R1Y_kj[k][j] = issuer[k].ivk_Y[j+1].duplicate().powZn(ComListArr.get(k).get(j)).getImmutable();//each Y_k,j^a_k,j
////                redSigma1_Y[k] = redSigma1_Y[k].duplicate().mul(R1Y_kj[k][j]).getImmutable();//j连乘Y_k,j^a_k,j
////            }
////        }


//        Element[] showproof = {phi_1, phi_2, phi_3, phi_4, phi_5, c_auth, W_z, W_eta, W_n, W_o, W_beta, W_e,E};
//        Element[] showcred = {Rsig1,Rsig2,aggsigma1,randomsig1,randomsig2};


        ShowCred result = new ShowCred(phi_1, phi_2, B, phi_3, phi_4, phi_5, c_auth, W_z, W_eta, W_n, W_o, W_beta, W_e, E, Rsig1, Rsig2, aggsigma1, randomsig1, randomsig2, aggkmulY_ki,mulIssuerIvk__Y);
        System.out.println("phi_1 = " + result.phi_1);
        System.out.println("phi_2 = " + result.phi_2);
        System.out.println("phi_3 = " + result.B);
        System.out.println("beta = " + beta);
        System.out.println("B = " + result.phi_3);
        System.out.println("phi_4 = " + result.phi_4);
        System.out.println("phi_5 = " + result.phi_5);
        System.out.println("D1 = " + D1);
        System.out.println("D2 = " + D2);
        System.out.println("D3 = " + D3);
        System.out.println("c_auth = " + result.c_auth);
        System.out.println("W_z = " + result.W_z);
        System.out.println("W_eta = " + result.W_eta);
        System.out.println("W_n = " + result.W_n);
        System.out.println("W_o = " + result.W_o);
        System.out.println("W_beta = " + result.W_beta);
        System.out.println("W_e = " + result.W_e);
        System.out.println("E = " + result.E);
        System.out.println("Rsig1 = " + result.Rsig1);
        System.out.println("Rsig2 = " + result.Rsig2);
        System.out.println("aggsigma1 = " + result.aggsigma1);
        System.out.println("randomsig1 = " + result.randomsig1);
        System.out.println("randomsig2 = " + result.randomsig2);
        System.out.println("aggkmulY_ki = " + result.aggkmulY_ki);
        System.out.println("mulIssuerIvk__Y = " + result.mulIssuerIvk__Y);

        return result;

    }

    public Transaction PGen(Vehicle vehicle, Element[] Cmt, Element[] sk_ots) {
        Element Q_u = vehicle.addr_upk.duplicate().powZn(sk_ots[0]);
        Element Q__u = Cmt[1].duplicate().powZn(sk_ots[0].duplicate().mul(vehicle.addr_usk).getImmutable()).mul(vehicle.addr_upk).getImmutable();
        Element[] preadd_upk = new Element[2];
        preadd_upk[0] = Q_u;
        preadd_upk[1] = Q__u;
        Element[] preadd_usk = new Element[2];
        preadd_usk[0] = vehicle.addr_usk;
        preadd_usk[1] = sk_ots[0];
        Transaction result = new Transaction(preadd_upk, preadd_usk);
        return result;
    }

    public tx Trans(RAAScheme param, Vehicle vehicle, ServiceProvider CS, Transaction key, Element[] Cmt, Element[] sk_ots, String info_pay, ShowCred proof, String t) {
        Element R1 = param.g1.powZn(sk_ots[0].duplicate().mul(sk_ots[1]).getImmutable()).getImmutable();
        Element R2 = Cmt[1].powZn(sk_ots[0].duplicate().mul(sk_ots[1]).getImmutable()).getImmutable();
        Element R3 = param.g1.duplicate().powZn(sk_ots[1]).getImmutable();
        Element info = Util.StringToElement(param.pairing, info_pay);
        byte[] b_info_pay = info.toBytes();
        byte[] b_preadd_upk1 = key.preadd_upk[0].toBytes();
        byte[] b_preadd_upk2 = key.preadd_upk[1].toBytes();
        byte[] b_pkcs = CS.pvk.toBytes();
        byte[] b_pkcmt = Cmt[1].toBytes();
        byte[] b_R1 = R1.toBytes();
        byte[] b_R2 = R2.toBytes();
        byte[] b_R3 = R3.toBytes();

        byte[] bytes = new byte[b_info_pay.length + b_preadd_upk1.length + b_preadd_upk2.length + b_pkcs.length + b_pkcmt.length + b_R1.length + b_R2.length + b_R3.length];
        System.arraycopy(b_info_pay, 0, bytes, 0, b_info_pay.length);
        System.arraycopy(b_preadd_upk1, 0, bytes, b_info_pay.length, b_preadd_upk1.length);
        System.arraycopy(b_preadd_upk2, 0, bytes, b_preadd_upk1.length, b_preadd_upk2.length);
        System.arraycopy(b_pkcs, 0, bytes, b_preadd_upk2.length, b_pkcs.length);
        System.arraycopy(b_pkcmt, 0, bytes, b_pkcs.length, b_pkcmt.length);
        System.arraycopy(b_R1, 0, bytes, b_pkcmt.length, b_R1.length);
        System.arraycopy(b_R2, 0, bytes, b_R1.length, b_R2.length);
        System.arraycopy(b_R3, 0, bytes, b_R2.length, b_R3.length);
        Element c_pay = param.pairing.getZr().newElementFromHash(bytes, 0, bytes.length).getImmutable();

        Element w1 = sk_ots[0].duplicate().mul(sk_ots[1]).add(c_pay.mul(sk_ots[0]).mul(vehicle.addr_usk).negate()).getImmutable();
        Element w2 = sk_ots[1].duplicate().add(c_pay.mul(vehicle.addr_usk).negate()).getImmutable();
        Element epoch_t = Util.StringToElement(param.pairing, t).getImmutable();
        byte[] b_epoch_t = epoch_t.toBytes();
        byte[] bytes1 = new byte[b_info_pay.length + b_epoch_t.length];
        System.arraycopy(b_info_pay, 0, bytes, 0, b_info_pay.length);
        System.arraycopy(b_epoch_t, 0, bytes, b_info_pay.length, b_epoch_t.length);
        Element h_pay = param.pairing.getG2().newElementFromHash(bytes1, 0, bytes1.length);
        Element sigma_ots = h_pay.duplicate().powZn(sk_ots[0].add(epoch_t.mul(sk_ots[1]))).getImmutable();
        tx result = new tx(c_pay, info, w1, w2, R2, sigma_ots);
        return result;

    }
}
