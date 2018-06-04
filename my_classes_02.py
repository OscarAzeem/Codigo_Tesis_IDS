# Conjunto de las clases ocupadas
class Metodos_Thesis():
    """Todas las funciones que ocupo en el programa de thesis"""

    def __init__(self):
        self.dic_ataques_all = {"probe": ['satan', 'ipsweep', 'nmap', 'portsweep', 'mscan', 'saint', ],
                                "dos": ['back', 'land', 'neptune', 'pod', 'teardrop', 'smurf', 'apache2', 'mailbomb',
                                        'processtable', 'udpstorm'],
                                "normal": ["normal"],
                                "r2l": ["guess_passwd", 'ftp_write', 'imap', 'multihop', 'phf', 'warezmaster',
                                        'warezclient', 'spy', 'snmpgetattack', 'snmpguess', 'worm',
                                        'xlock', 'xsnoop', 'named', 'sendmail'],
                                "u2r": ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel', 'ps',
                                        'sqlattack', 'xterm']}

    def imprime_valores(self, dataset, dic_ataques_all=None):
        """Imprime los valroes de un dataset (dataset,dic_ataques_all)"""
        if not dic_ataques_all:
            dic_ataques = self.dic_ataques_all
        total = 0
        t = 0
        for llaves, valores in dic_ataques.items():
            print("Grupo de ataque: " + llaves)
            for i in range(0, len(dic_ataques[llaves])):
                l = len(dataset[dataset.TypeOfAttack == dic_ataques[llaves][i]])
                t = t + l
                print("El total de valores del ataque: " + str(dic_ataques[llaves][i]) + " es: " + str(l))
            print("Total= " + str(t))
            total = total + t
            t = 0
        print("el total general es: " + str(total))

    def ip(self, data):
        """Muestra información básica de algún dataframe"""
        # print(type(data))
        print('Su tipo es %s=' % (str(type(data))))
        print('Sus filas son %d=' % (data.shape[0]))
        print('Sus columnas son %d=' % (data.shape[1]))

    def clean_one_column(self, single_column):
        return single_column[:-1]

    def cleaning_one_column(self, dataframe, columna='TypeOfAttack', indice=None):
        """Recibe un dataframe con el punto decimal extra y regresa el mismo sin ese punto \n
        No es necesario igualar al llamar la funcion, exmpl: testing=metodo.cleaning...(testing).
        Automaticamente al llamarse se limpia en el mimos dataframe"""
        # clean one column es una FUNCION, la cual se envía al método APPLY
        temporal = dataframe[columna].apply(self.clean_one_column)
        dataframe[columna] = temporal
        temporal = None
        return dataframe

        # building again the function

    def building_the_labels(self, dataframe_to_build):
        """"dataframe_to_build, nombre del dataframe a quien se desea agregar los parametros:
        # ,TypeOfAttacks,Group,IndexAttack,IndexByGroup
        # dataframe_indice
        # cada una de las columnas contenidas en el csv: index_attacks.csv, las cuales son:
        # ,TypeOfAttacks,Group,IndexAttack,IndexByGroup"""
        import pandas as pd
        dataframe_indice = pd.read_csv("./dataset_labeled/index_attacks.csv", index_col=0)
        j = 0
        n = 0
        # creating the general dataframe->pandas_general
        # pandas_general=pd.DataFrame(columns=dataframe_to_build.columns)
        # la chapucera, porque no pude agregar los series normal
        pandas_general = pd.DataFrame(columns=['Duration', 'ProtocolType', 'Service', 'Flag', 'SourceBytes', \
                                               'DestinationBytes', 'Land', 'WrongFragment', 'Urgent', 'Hot', \
                                               'FailedLogins', 'LoggedIn', 'NumberOfCompromised', 'RootShell', \
                                               'SuAttempted', 'Root', 'NumberOfFileCreations',
                                               'NumberOfShellPrompts', \
                                               'NumberOfAccessFiles', 'NumberOfOutbound', 'IsHotLogin',
                                               'IsGuestLogin', \
                                               'Count', 'SrvCount', 'SerrorRate', 'SrvSerrorRate', 'RerrorRate', \
                                               'SrvRerrorRate', 'SameSrvRate', 'DiffSrvRate', 'SrvDiffHostRate', \
                                               'DstHostCount', 'DstHostSrvCount', 'DstHostSameSrvRate', \
                                               'DstHostDiffSrvRate', 'DstHostSameSrcPortRate', \
                                               'DstHostSrvDiffHostRate', 'DstHostSerrorRate',
                                               'DstHostSrvSerrorRate', \
                                               'DstHostRerrorRate', 'DstHostSrvRerrorRate', 'TypeOfAttack', \
                                               'TimesApparead', 'Group', 'IndexAttack', 'IndexByGroup',
                                               'IndexBinary'])
        # for for each type of attack in the receiving dataframe
        for tipeofattack in dataframe_indice.TypeOfAttacks.unique():
            print("Me encuentro trabajando en :" + tipeofattack)
            # creating the dataframe filtered
            #filtrando el pandas por el tipo de ataque
            pandas_temporal = dataframe_to_build[dataframe_to_build.TypeOfAttack == tipeofattack]
            if not (pandas_temporal.empty):
                # Building the index for pandas_general
                index_attack = dataframe_indice[dataframe_indice.TypeOfAttacks == tipeofattack].IndexAttack
                index_attack_by_group = dataframe_indice[dataframe_indice.TypeOfAttacks == tipeofattack].IndexByGroup
                nombre_grupo = dataframe_indice[dataframe_indice.TypeOfAttacks == tipeofattack].Group
                # getting just the number, because problems with the pandas series
                index_attack = index_attack.iat[0]
                index_attack_by_group = index_attack_by_group.iat[0]
                nombre_grupo = nombre_grupo.iat[0]
                # Declaring pandas_temporal
                # pandas_temporal=dataframe_indice[dataframe_indice.TypeOfAttacks==tipeofattack]
                # slicing the temporal pandas
                pandas_temporal["Group"] = nombre_grupo
                pandas_temporal["IndexAttack"] = index_attack
                pandas_temporal["IndexByGroup"] = index_attack_by_group
                # Asignando etiquetas de 1 o 0
                # no. 16, ataque tipo normal.
                if index_attack != 16:
                    # 1=ataque
                    pandas_temporal['IndexBinary'] = 1
                else:
                    # 0=no ataque=normal
                    pandas_temporal['IndexBinary'] = 0
                # concatenaning both, pandas_general and pandas_temporal
                pandas_general = pd.concat([pandas_general, pandas_temporal], join='inner', axis=0, )
                # print("\n Éste es el valor de pandas general")
                # print(pandas_general)
                # erasing the pandas_temporal
                pandas_temporal = None
                j = j + 1
            else:
                print("\n NO SE encuentra valores para: " + tipeofattack + "\n")
                n = n + 1
        print("Trabaje: " + str(j) + " veces")
        print("No encontre valores: " + str(n) + " veces")
        # sorting the pandas_general
        # print(pandas_general)
        pandas_general = pandas_general.sort_index()
        dataframe_indice=None
        return pandas_general

##############################################################################################

    def encuentra_filas_iguales(self,dataset_inicio,inicio='Duration',fin='Group'):
        import pandas as pd
        import numpy as np
        from sklearn import preprocessing
        dataset = dataset_inicio.loc[:, inicio:fin]
        columnas = dataset.columns
        print("***PREPROCESSING***")
        for indice in range(0, len(columnas)):
            if type(dataset.loc[0, columnas[indice]]) == str:
                print('Building the labels dimension number= %d, perteneciente al Nombre: %s' % (
                indice, columnas[indice]))
                # print('Nombre %s' % (columnas[indice]))
                # print('Su tipo es %s=' % (str(type(data))))
                # label enconder, object
                label_encoder = preprocessing.LabelEncoder()
                # label encoer, fit
                label_encoder.fit(dataset[columnas[indice]])
                # building the dataframe
                dataset[columnas[indice]] = label_encoder.transform(dataset[columnas[indice]])
            # for donde multiplica todas las columnas, para evitar los iguales al sumar
            dataset[columnas[indice]] = dataset[columnas[indice]] * (np.random.randn())

            # obteniendo la suma del dataset
        suma = dataset.sum(axis=1)
        # adding the "suma" series to the dataset_inicio
        dataset_inicio["suma"] = suma
        # borrando los duplicados
        series_suma = dataset_inicio[dataset_inicio.suma.duplicated(keep=False)]
        # obteniendo los valores repetidos mediante group by
        series_suma = dataset_inicio.groupby('suma').apply(lambda x: list(x.index))
        #
        print("***VALORES REPETIDOS***")
        print("Existen %d valores repetidos" % (len(dataset_inicio) - len(series_suma)))
        # arriba todo bien
        for indice in range(0, len(series_suma)):
            a = []
            if len(series_suma[series_suma.index.values[indice]]) > 1:
                print("***NUEVA REPETICION en el indice suma: %f" % (series_suma.index.values[indice]))
                print(
                    "Tiene un total de instancias iguales a: %d" % (len(series_suma[series_suma.index.values[indice]])))
                # aqui parece el problema
                for cantidad_instancias_repetidas in range(0, len(series_suma[series_suma.index.values[indice]])):
                    print("No de instancia: %d que equivale al indice dataset: %d" % (cantidad_instancias_repetidas,
                                                                                      series_suma[
                                                                                          series_suma.index.values[
                                                                                              indice]][
                                                                                          cantidad_instancias_repetidas]))
                    ataque = dataset_inicio.loc[
                        series_suma[series_suma.index.values[indice]][cantidad_instancias_repetidas], "TypeOfAttack"]
                    clase = dataset_inicio.loc[
                        series_suma[series_suma.index.values[indice]][cantidad_instancias_repetidas], "Group"]
                    print("Pertenece al tipo de ataque: %s de la clase %s" % (ataque, clase))
                    a.append(series_suma[series_suma.index.values[indice]][cantidad_instancias_repetidas])
                    if cantidad_instancias_repetidas == (len(series_suma[series_suma.index.values[indice]])-1):
                        with pd.option_context('display.max_rows', None, 'display.max_columns', 42):
                            print(dataset_inicio.loc[a, 'TypeOfAttack':])

    def Build_the_index_of_a_dimension(self, dataframe_to_build, dataframe_indice):
        """"dataframe_to_build, nombre del dataframe a quien se desea agregar el indice correspondiente
        #Hace uso analogo del método LabelEncoder, sin embargo se programo para que el etiquetado fuese
        #completamente controlado.
        #Recibe el dataframe a agregar los indices contenidos en el dataframe indice.
        #estos vienen de un .csv, comunmente"""
        import pandas as pd
        j = 0
        n = 0
        # creating the general dataframe->pandas_general

        # columnas del pandas, para anexarlas al concatenar
        pandas_general = pd.DataFrame(columns=dataframe_to_build.columns)
        # creando la columna al inicio para no tener problemas al usar el concact en el axis 0
        # se tiene que igualar a cero, debido a que las columnas se crean como flotantes
        # si se crea unicamente la columna vacia:
        # pandas_temporal['Index'+dataframe_indice.columns[0]]=[]
        pandas_general['Index' + dataframe_indice.columns[0]] = 0

        for elemento in dataframe_indice[dataframe_indice.columns[0]].unique():
            print("Me encuentro trabajando en :" + elemento)
            # creating the dataframe filtered.
            ###
            # filtra el dataframe original (dataframe_to_build) mediante la columna del "tipo" (protocol, serivce,etc)
            # despues iguala esa columna con el elemento del for
            # despues filtra todo el dataframe
            pandas_temporal = dataframe_to_build[dataframe_to_build[dataframe_indice.columns[0]] == elemento]
            if not (pandas_temporal.empty):
                # Building the index for pandas_general
                index_elemento = dataframe_indice[dataframe_indice[dataframe_indice.columns[0]] == elemento] \
                    [dataframe_indice.columns[1]].iat[0]
                # Declaring pandas_temporal
                # pandas_temporal=dataframe_indice[dataframe_indice.TypeOfAttacks==tipeofattack]
                # slicing the temporal pandas
                pandas_temporal['Index' + dataframe_indice.columns[0]] = index_elemento
                # concatenaning both, pandas_general and pandas_temporal
                pandas_general = pd.concat([pandas_general, pandas_temporal], join='inner', axis=0, )
                pandas_temporal = None
                j = j + 1
            else:
                print("\n NO SE encuentra valores para: " + elemento + "\n")
                n = n + 1
        print("Trabaje: " + str(j) + " veces")
        print("No encontre valores: " + str(n) + " veces")
        # sorting the pandas_general
        # print(pandas_general)
        pandas_general = pandas_general.sort_index()
        print("La longitud de la matriz inicial es: " + str(len(dataframe_to_build)))
        print("La longitud de la matriz final es: " + str(len(pandas_general)))

        return pandas_general