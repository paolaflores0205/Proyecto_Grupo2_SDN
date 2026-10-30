import pathlib,unittest
from resumir import summary
class Statistics(unittest.TestCase):
 def test_historical_denominator(self):
  r=summary(pathlib.Path(__file__).parent/'historico-20261022/ensayos.csv')
  self.assertEqual((r['initiated_trials'],r['valid_trials'],r['incomplete_trials']),(24,23,1))
  self.assertAlmostEqual(r['metrics']['confirmation']['mean'],985.7273826085515)
  self.assertAlmostEqual(r['metrics']['confirmation']['p95_exploratory_nearest_rank'],1024.51469999869)
if __name__=='__main__':unittest.main()
