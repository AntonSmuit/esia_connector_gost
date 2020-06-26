Переделанная реализация интеграции с ЕСИА,
оргинальная - 

отличия
1) переделал в процедурный стиль
2) добавил поддержку шифрования по госту
3) сделал отдельным сервисом в докере
4) проапдейтил для текущей версии

как использовать (в основном все описано в регламенте, но писалось явно не для людей, потому приведу краткую версию, плюс
выжимка из форумов и стаковерфлоу)
1) нужно зарегистрировать свою систему на госуслугах
2) с апреля 2012 есиа перестал поддерживать шифрование по RSA, перешли на российский гост 2012, поэтому в отличие от 
 оригинального проекта с самоподписанными РСА протестировать работу не получится(хотя возможно на тестовом контуре и не 
 отключали), в любом случае для самого ЕСИА нужно будет получить квалифицированную электронную цифровую подпись 
 в аккредитованном центре, важно им сказать что подпись нужна для ЕСИА, она должна быть экспортируемой(должны выставить 
 специальный флаг), плюс крайне желательно чтобы она сразу была в формате pem или человеческом pfx, но я таких не нашел. 
 если выдадут стандартную крипто про на флешке (папочка с файлами primary.key, primary2.key, mask.key, mask2.key 
 итд итп) - то потребуются дополнительные усилия чтобы выковырнуть оттуда приватный ключ. ну и напоминаю что хранение 
 приватного ключа на сервере повышает шансы что его сопрут, поэтому не стоит эту эцп использовать для чегото важного, 
 если у вас уже была эцп для налоговой или других дел, то лучше получить новую. 
3) нужно из эцп получить публичный и приватный ключи для того чтобы подложить их на сервер. сначала нужно экспортировать
эцп в систему с флешки, далее публичный ключ экспортируется обычным(даже триальным) клиентом крипто про, а вот с 
приватным придется повозиться, так как он экспортируется тем же клиентом0 в нестандартном pfx формате. в интернете можно
найти несколько способов(на хабре, на форуме крипто про, на форуме наг.ру) как преобразовать контейнер крипто про в 
нужный формат, или вытащить ключ из крипто про формата, но они все разной степени хакернутости, нормальным людям проще 
всего будет использовать утилиту для бэкапа приватных ключей криптопро P12fromGOST от Лисси (платная, но раньше они ее 
выкладывали бесплатно, можно найти ту версию). она экспортирует файлы в стандартный pfx файл. из пфх файла уже можно 
получить стандартный .pem файл стандартными командами для опенссл

openssl pkcs12 -in backup_keys.pfx -out backup_keys.pem -engine gost -nodes -clcerts  

да, вам потребуется опенссл с поддержкой госта 2012, что может быть проблемой, так как в последних версиях(1.1.1) ее выпилили,
нужно брать версии 1.0.1, отдельно ставить гост энжин, который не со всеми версиями опенссл нормально работает, но как 
вариант можно использовать докер образ уже собранный с рабочими версиями опенссл и гост энжин. 
так же на стаковерфло был совет из пем файла удалить все лишние блоки (кроме блоков самих сертификатов 
----BEGIN ----сертификат ---END----, и поменять их местами - чтобы приватный ключ в пем файле шел первым, я на всякий 
случай сделал)
так же в пем файле приватный ключ может быть зашифрован для большей защиты, я расшифровал. если хотите использовать в 
зашифрованном виде то кудато нужно будет еще впихнуть распаковку ключа по паролю

4) подложить ключи(одним файлом пем) в папочку серт, туда же закинуть публичные ключи от теста и прода есиа 
(скачиваются с офсайта, ссылка есть в документации, единым файлом esia.zip)

5) написать заявку на подключение вашей системы к ЕСИА, там нужно указать урл по которому будет доступна ваша система
(чтобы есиа знала что на этот урл можно редиректирить пользователей), ее мнемоника (нужно придумать самому по правилам для
смэва - по ней есиа будет искать сертификаты для проверки подписи вашей системы и прав доступа), приложить открытый ключ
(сер файл в формате дер, если вы понимаете о чем я:), пем файл прикладывать не стоит так как там указан и приватный ключ 
- так же сертификат можно будет прикрепить самостоятельно и на проде, и на тесте(отдельно), найдя свою систему по мнемонике ),
плюс указать список запросов к которым пользователь должен дать вам доступ (fullname snils итд итп). после рассмотрения
и утверждения заявки можно пробовать подключение к тестовому контуру есиа, потом для прода нужно будет просто поменять урл
подключения.  

6) запустить фласк сервер отдельно или как сервис в докере

бонус, как оно работает
1) вы на своем сайте должны сформировать специальный урл, и прикрутить его к кнопке войти через есиа
в нем зашито (и подписано вашим приватным ключом) кто вы такие, чего вы хотите, и куда потом нужно юзера послать. 
2) юзер кликает на кнопку, его перекидывает на сайт есиа, там он логинится, соглашается предоставить доступ к запрошенной
вашей системой информации, после чего его браузер редиректит на отправленный редирект урл (который должен совпадать с 
урлом в настройках вашей системы в есиа, для тестового контура можно использовать локалхост). если логин прошел успешно, 
то есиа в параметрах к редирект урлу передает на ваш сайт специальный код, или сообщение об ошибке. 
3) вы получаете по апи на этом урле этот код, и используете его в новом запросе к есиа, уже от своей системы, для получения
специальных аксесс и рефреш джвт токенов. 
4) аксесс токен уже можно использовать в конкретных запросах на получение параметров пользователя из есиа - имя, адрес, 
телефон итд итп 

логи тестового контура есиа можно посмотреть по спец урлу, но желательно делать это в нерабочие часы

по ошибкам - мне встречалась ошибка у вашей системы нет прав для доступа к этим данным, оказалось что на тестовом 
контуре на был загружен сертификат публичного ключа. 
