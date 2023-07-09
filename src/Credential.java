import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Credential{
    public  Element mulIssuerIvk;
    public  Element mulIssuerIvk0;
    public  Element mulIssuerIvkx;

    public  Element mulIssuerIvk__Y;

    public Credential(Element unitG2Element,Element unitG1Element){
        this.mulIssuerIvkx=unitG2Element;
        this.mulIssuerIvk0=unitG2Element;
        this.mulIssuerIvk=unitG2Element;
        this.mulIssuerIvk__Y=unitG1Element;
    }

}
