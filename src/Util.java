
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

public class Util {

    public static Element StringToElement(Pairing pairing, String str) {
        byte[] att = str.getBytes();
        Element attribute = pairing.getZr().newElementFromBytes(att, 0);

        return attribute;
    }


    public static Element[] StringToElementOne(Pairing pairing, String[] str) {
        Element[] attribute = new Element[str.length];
        for (int i = 0; i < str.length; i++) {
            byte[] att = str[i].getBytes();
            attribute[i] = pairing.getZr().newElementFromBytes(att, 0);
        }
        return attribute;
    }


    public static Element[][] StringToElementTwo(Pairing pairing, String[][] str) {

        Element[][] attribute = new Element[str.length][str[1].length];

        for (int j = 1; j < str.length; j++) {
            for (int i = 1; i < str[j].length; i++) {
                byte[] att = str[j][i].getBytes();
                attribute[j][i] = pairing.getZr().newElementFromBytes(att, 0);
            }
        }

        return attribute;

    }
}
