import it.unisa.dia.gas.jpbc.Element;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
//@AllArgsConstructor//
@NoArgsConstructor
public class ShowCred {
    public Element phi_1, phi_2,B, phi_3, phi_4, phi_5, c_auth, W_z,W_eta,W_n,W_o,W_beta,W_e,E,aggkmulY_ki;


    public Element[] Rsig1;
    public Element[] mulIssuerIvk__Y;


    public Element[] Rsig2;
    public Element aggsigma1;
    public Element randomsig1;
    public Element randomsig2;


    public ShowCred(Element phi_1, Element phi_2, Element B,Element phi_3,Element phi_4,Element phi_5,Element c_auth,Element W_z,Element W_eta,Element W_n,Element W_o,Element W_beta,Element W_e,Element E,Element[] Rsig1,Element[] Rsig2,Element aggsigma1,Element randomsig1,Element randomsig2,Element aggkmulY_ki,Element[] mulIssuerIvk__Y){
        this.phi_1=phi_1;
        this.phi_2=phi_2;
        this.phi_3=phi_3;
        this.B=B;
        this.phi_4=phi_4;
        this.phi_5=phi_5;
        this.c_auth=c_auth;
        this.W_z=W_z;
        this.W_eta=W_eta;
        this.W_n=W_n;
        this.W_o=W_o;
        this.W_beta=W_beta;
        this.W_e=W_e;
        this.E=E;
        this.Rsig1=Rsig1;
        this.Rsig2=Rsig2;
        this.aggsigma1=aggsigma1;
        this.randomsig1=randomsig1;
        this.randomsig2=randomsig2;
        this.aggkmulY_ki=aggkmulY_ki;
        this.mulIssuerIvk__Y=mulIssuerIvk__Y;
    }


}
