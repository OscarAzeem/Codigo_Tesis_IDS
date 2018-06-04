#Definiendo las librerias
#importing everything
import pandas as pd
import numpy as np
#visualization
import matplotlib.pyplot as plt
import seaborn as sns
#printing in noteboo
#%matplotlib inline
#leyendo corrected (testing dataset)
testing=pd.read_csv('./Original_Corrected_datasets/KDD/corrected.csv')

#leyendo mi libreria
from my_classes_01 import Metodos_Thesis as MT
mc=MT()

#llamando a las funciones
mc.ip(testing)