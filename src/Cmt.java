import it.unisa.dia.gas.jpbc.Element;

public class Cmt {

    public Element[] CmtKeyGen(RAAScheme param) {
        Element Cmtsk = param.pairing.getZr().newRandomElement().getImmutable();
        Element Cmtpk = param.g1.duplicate().powZn(Cmtsk).getImmutable();

        Element[] Cmt = new Element[2];
        Cmt[0]=Cmtsk;
        Cmt[1]=Cmtpk;

        return Cmt;
    }
    public void Verifypay(RAAScheme param,ServiceProvider CS, Element[] Cmt,Element[] vk_ots, tx txch, Transaction prekey,String t){
        Element preupk = prekey.preadd_upk[1].duplicate().div(prekey.preadd_upk[0]).getImmutable();
        //R1'
        Element R_1=param.g1.duplicate().powZn(txch.w1).mul(prekey.preadd_upk[0].powZn(txch.c_pay)).getImmutable();
        Element R_3=param.g1.duplicate().powZn(txch.w2).mul(prekey.preadd_upk[1].powZn(txch.c_pay)).mul(Cmt[1].powZn(txch.w1)).div(txch.R2).getImmutable();
        byte[] b_info_pay = txch.info.toBytes();
        byte[] b_preadd_upk1 = prekey.preadd_upk[0].toBytes();
        byte[] b_preadd_upk2 = prekey.preadd_upk[1].toBytes();
        byte[] b_pkcs = CS.pvk.toBytes();
        byte[] b_pkcmt = Cmt[1].toBytes();
        byte[] b_R_1 = R_1.toBytes();
        byte[] b_R_2 = txch.R2.toBytes();
        byte[] b_R_3 = R_3.toBytes();

        byte[] bytes = new byte[b_info_pay.length + b_preadd_upk1.length + b_preadd_upk2.length + b_pkcs.length +b_pkcmt.length+ b_R_1.length + b_R_2.length + b_R_3.length  ];
        System.arraycopy(b_info_pay, 0, bytes, 0, b_info_pay.length);
        System.arraycopy(b_preadd_upk1, 0, bytes, b_info_pay.length, b_preadd_upk1.length);
        System.arraycopy(b_preadd_upk2, 0, bytes, b_preadd_upk1.length, b_preadd_upk2.length);
        System.arraycopy(b_pkcs, 0, bytes, b_preadd_upk2.length, b_pkcs.length);
        System.arraycopy(b_pkcmt , 0, bytes, b_pkcs.length, b_pkcmt .length);
        System.arraycopy(b_R_1, 0, bytes, b_pkcmt .length, b_R_1.length);
        System.arraycopy(b_R_2, 0, bytes, b_R_1.length,b_R_2.length);
        System.arraycopy(b_R_3, 0, bytes, b_R_2.length, b_R_3.length);
        Element c__pay = param.pairing.getZr().newElementFromHash(bytes, 0, bytes.length).getImmutable();
        Element epoch_t = Util.StringToElement(param.pairing, t).getImmutable();
        byte[] b_epoch_t = epoch_t.toBytes();
        byte[] bytes1=new byte[b_info_pay.length+b_epoch_t.length];
        System.arraycopy(b_info_pay, 0, bytes, 0, b_info_pay.length);
        System.arraycopy(b_epoch_t, 0, bytes, b_info_pay.length, b_epoch_t.length);
        Element h_pay=param.pairing.getG2().newElementFromHash(bytes1,0,bytes1.length);
        Element left = param.pairing.pairing(vk_ots[0].duplicate().mul(vk_ots[1].powZn(epoch_t)).getImmutable(),h_pay);
        Element right = param.pairing.pairing(param.g1,txch.sigma_ots);
        if(txch.c_pay.isEqual(c__pay)&&left.isEqual(right)){
            System.out.println("Vehicle OBU payment verification successed");
        } else {
            System.out.println("Vehicle OBU payment verification failed");
        }
        }
    }

