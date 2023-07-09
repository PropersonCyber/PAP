import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class RAAScheme {

    public Pairing pairing;
    public Element g1;
    public Element g_1;
    public Element g__1;
    public Element g2;


    public void Setup(String properties) {
        this.pairing = PairingFactory.getPairing(properties);
        this.g1 = pairing.getG1().newRandomElement().getImmutable();
        this.g2 = pairing.getG2().newRandomElement().getImmutable();
        this.g_1 = pairing.getG1().newRandomElement().getImmutable();
        this.g__1 = pairing.getG1().newRandomElement().getImmutable();
    }

}
