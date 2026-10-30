"""Resume CSV sin alterar el registro histórico ni imputar ensayos incompletos."""
import csv,json,math,pathlib,statistics,sys
def summary(path):
 with pathlib.Path(path).open(encoding='utf-8-sig') as stream:rows=list(csv.DictReader(stream))
 valid=[r for r in rows if r['resultado']=='completo']
 result={'initiated_trials':len(rows),'valid_trials':len(valid),'incomplete_trials':len(rows)-len(valid),'unit':'ms','metrics':{}}
 for name,key in [('confirmation','confirmacion_denegacion_ms'),('dti_response','respuesta_DTI_ms')]:
  values=sorted(float(r[key]) for r in valid)
  if values:result['metrics'][name]={'mean':statistics.mean(values),'median':statistics.median(values),'min':min(values),'max':max(values),'p95_exploratory_nearest_rank':values[math.ceil(.95*len(values))-1]}
 return result
if __name__=='__main__':print(json.dumps(summary(sys.argv[1] if len(sys.argv)>1 else pathlib.Path(__file__).parent/'historico-20261022/ensayos.csv'),indent=2))
