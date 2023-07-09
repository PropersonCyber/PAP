import it.unisa.dia.gas.jpbc.Element;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
public class tx {
    public Element c_pay,info,w1,w2,R2,sigma_ots;
    public tx(Element c_pay,Element info,Element w1,Element w2,Element R2,Element sigma_ots){
        this.c_pay=c_pay;
        this.info=info;
        this.w1=w1;
        this.w2=w2;
        this.R2=R2;
        this.sigma_ots=sigma_ots;
    }
}
