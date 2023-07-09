import it.unisa.dia.gas.jpbc.Element;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
public class Transaction {
    public  Element[] preadd_upk;
    public  Element[] preadd_usk;


    public  Transaction( Element[] preadd_upk,Element[] preadd_usk ){
        this.preadd_upk=preadd_upk;
        this.preadd_usk=preadd_usk;
    }

}



