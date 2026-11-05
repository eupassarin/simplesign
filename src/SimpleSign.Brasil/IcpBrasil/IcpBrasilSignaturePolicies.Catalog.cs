namespace SimpleSign.Brasil.IcpBrasil;

// Generated from the ITI's LPA_PAdES.der and LPA_CAdES.der (http://politicas.icpbrasil.gov.br/,
// LPA nextUpdate 2027-01-01). Each PA file was downloaded, checked against the SHA-256 digest the
// LPA lists for it, and its signPolicyHash (the value signatures carry in sigPolicyHash) copied here.
// Columns: OID, PA URI, hash algorithm, signPolicyHash, signing period start/end, LPA revocation date.
public static partial class IcpBrasilSignaturePolicies
{
    private const string Sha256 = "2.16.840.1.101.3.4.2.1";
    private const string Sha1 = "1.3.14.3.2.26";

    private static readonly IcpBrasilSignaturePolicy[] Catalog =
    [
        new("2.16.76.1.7.1.11.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_0.der", Sha256, "501D69B4B71FC6E57323C2C74131A9C8C62409BE378BA788DC288555611B9E58", Utc(2015, 8, 25), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.12.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_0.der", Sha256, "CEFBBA0147077BD216EB04D2B25C56C3D4AC60DBBE08CDD697D2DCD0029B56E8", Utc(2015, 8, 25), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.13.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_0.der", Sha256, "B3D8A9EF6B475A8CD62F07B3EDB8B0BD974DD15A165EEB197BD987D7591E0FEE", Utc(2015, 8, 25), Utc(2029, 3, 2), Utc(2016, 7, 15)),
        new("2.16.76.1.7.1.14.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_0.der", Sha256, "6D1DD552117D1DE402F515F9F77EF9D30B2162995F93A2290C134C9C24387BDF", Utc(2015, 8, 25), Utc(2029, 3, 2), Utc(2016, 7, 15)),
        new("2.16.76.1.7.1.13.1.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_1.der", Sha256, "3FE5E1EEEA9F6723568DC9E2C313C0E19C817FAA923AB29B52EA76D1FB53027C", Utc(2016, 7, 15), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.14.1.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_1.der", Sha256, "2AC50C5BE4CCDDE5C240A4A304F7021642841642AA0ED8B403E6C518DD9D81B6", Utc(2016, 7, 15), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.11.1.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_1.der", Sha256, "44FC5816EB2D705D8C8F022A7F93B3FB49EDFAE1A7B9149EF6FAB833E9BB63F8", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.12.1.1", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_1.der", Sha256, "FA1D44E76AD91E2F6CD471B6987E9C0F1C70D4B70DA0956E7BECF4DC792C0C1F", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.13.1.2", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_2.der", Sha256, "9F743696B821E535252C17DF754CD9379FD2D3B6870179248C64A5C80604399D", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.14.1.2", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_2.der", Sha256, "1F1B8E74BE9626BC1702D40CE1C126EB1C9CAF7BADE6B1FD779C8F60E733DD7C", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.11.1.2", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_2.der", Sha256, "BF22358C963B52971F18C822D8529C5163FE55FA8EED1068D327ADC6BC082EE2", Utc(2025, 6, 12), Utc(2037, 10, 22), Utc(2025, 7, 23)),
        new("2.16.76.1.7.1.12.1.2", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_2.der", Sha256, "19E0BE31D91A6FFA694BBE0E9B35E4BC2F877F62DC6AC7A7833ADA6345E15AF8", Utc(2025, 6, 12), Utc(2037, 10, 22), Utc(2025, 7, 23)),
        new("2.16.76.1.7.1.13.1.3", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_3.der", Sha256, "235488859F7ADA5D4984C364CC1C8EEE4673FB7C70FF8B19DD236A86F3D87CC2", Utc(2025, 6, 12), Utc(2037, 10, 22), Utc(2025, 7, 23)),
        new("2.16.76.1.7.1.14.1.3", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_3.der", Sha256, "542600EFAA7CAC8E1DB8CEE572EF275F6157DE27CF5E2FD75466AE2DCF8FAB04", Utc(2025, 6, 12), Utc(2037, 10, 22), Utc(2025, 7, 23)),
        new("2.16.76.1.7.1.11.1.3", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RB_v1_3.der", Sha256, "23E4BE4B9B362172E4EBB0E72B86A133ECE5AAD843D8651C6E38A0BA3F08FC60", Utc(2025, 7, 23), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.12.1.3", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RT_v1_3.der", Sha256, "21D6E8D9F85E5626DC71307337A7CABD6FFEF8D085038746775CF0CE6BA4D3B5", Utc(2025, 7, 23), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.13.1.4", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RC_v1_4.der", Sha256, "712F18A9F0163C1E90DA6FF0B7165543378A18A0F06D3CB21668067CAC229BD2", Utc(2025, 7, 23), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.14.1.4", "http://politicas.icpbrasil.gov.br/PA_PAdES_AD_RA_v1_4.der", Sha256, "FFA9FD474812F6CE63D625679C9EF235A6547B017BE941B2C094AA868E67E123", Utc(2025, 7, 23), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.1.1", "http://politicas.icpbrasil.gov.br/PA_AD_RB.der", Sha1, "20D6789325513BBC8C29624E1F40B61813EC5CE7", Utc(2008, 10, 31), Utc(2014, 12, 31), null),
        new("2.16.76.1.7.1.1.1.1", "http://politicas.icpbrasil.gov.br/PA_AD_RB_v1_1.der", Sha1, "397E6EA850C78AC44E7F3872DB369EDFECB50E63", Utc(2011, 12, 26), Utc(2014, 12, 31), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.1.2", "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_0.der", Sha256, "5311E6CE55665C87F6085EF11C82FA3FB1341CADE7981ED9F51D3E56DE5F6AAD", Utc(2011, 12, 26), Utc(2023, 6, 21), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.1.2.1", "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_1.der", Sha256, "DD57C98A4313BC1398CE6543D3802458957CF716AE3294EC4D8C26251291E6C1", Utc(2012, 3, 7), Utc(2023, 6, 21), Utc(2017, 2, 26)),
        new("2.16.76.1.7.1.2.1", "http://politicas.icpbrasil.gov.br/PA_AD_RT.der", Sha1, "ACDC93F268CA1D95BB043018A95BBF6166654C51", Utc(2008, 10, 31), Utc(2014, 12, 31), null),
        new("2.16.76.1.7.1.2.1.1", "http://politicas.icpbrasil.gov.br/PA_AD_RT_v1_1.der", Sha1, "64CDB3C737D61215883CDBC8E1FDD3471BA744C7", Utc(2011, 12, 26), Utc(2014, 12, 31), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.2.2", "http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_0.der", Sha256, "D5AD96D431217669E86D832585F2AE252F9982F8D0B34B04BA2BC96C0ABC09E6", Utc(2011, 12, 26), Utc(2023, 6, 21), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.2.2.1", "http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_1.der", Sha256, "217D8E68B5DAFCA6BC72FE610E3EC9F9CB9F7D75B099091C24106F48A6527A0F", Utc(2012, 3, 7), Utc(2023, 6, 21), Utc(2017, 2, 26)),
        new("2.16.76.1.7.1.3.1", "http://politicas.icpbrasil.gov.br/PA_AD_RV.der", Sha1, "67D76103EE4BEB8503713F74ADD45D4169362765", Utc(2008, 10, 31), Utc(2014, 12, 31), null),
        new("2.16.76.1.7.1.3.1.1", "http://politicas.icpbrasil.gov.br/PA_AD_RV_v1_1.der", Sha1, "B62F8A1CA6302665ABACE9E0A50B0EFF2C6E4B7F", Utc(2011, 12, 26), Utc(2014, 12, 31), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.3.2", "http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_0.der", Sha256, "2D8A04EE1B6CFF00C91CFDB23B94AC0CBD0BC7D93B22961A0E879A8433AE36B8", Utc(2011, 12, 26), Utc(2023, 6, 21), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.3.2.1", "http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_1.der", Sha256, "E1E9E0D318F3CD7CB1B853B71AF182DD02DA231FCA07C6868C034A8559A397A3", Utc(2012, 3, 7), Utc(2023, 6, 21), Utc(2017, 2, 26)),
        new("2.16.76.1.7.1.4.1", "http://politicas.icpbrasil.gov.br/PA_AD_RC.der", Sha1, "2F07ADDC32C756A2AEC5E657BB9E5E63C091CC13", Utc(2008, 10, 31), Utc(2014, 12, 31), null),
        new("2.16.76.1.7.1.4.1.1", "http://politicas.icpbrasil.gov.br/PA_AD_RC_v1_1.der", Sha1, "B00B950710C5AFC7B03680418A2C4128EDFD0D02", Utc(2011, 12, 26), Utc(2023, 6, 21), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.4.2", "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_0.der", Sha256, "DEFBE63B1EF62346C587074C95207A1FBC36B1A80A672464BFD664A593BDF86B", Utc(2011, 12, 26), Utc(2023, 6, 21), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.4.2.1", "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_1.der", Sha256, "0C3180DCDC404413415DBC3E3A991AE6D06E79BE2BFC85B3D1C34E90C1F292BC", Utc(2012, 3, 7), Utc(2023, 6, 21), Utc(2017, 2, 26)),
        new("2.16.76.1.7.1.5.1", "http://politicas.icpbrasil.gov.br/PA_AD_RA.der", Sha1, "8BB2B2CA1DED880B9D2718662BE66371520F99CF", Utc(2008, 10, 31), Utc(2014, 12, 31), Utc(2012, 9, 21)),
        new("2.16.76.1.7.1.5.1.1", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v1_1.der", Sha1, "64ACFDC2A613D59AA49B19CA93FBB178086F1F7F", Utc(2011, 12, 26), Utc(2014, 12, 31), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.5.2", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_0.der", Sha256, "716D7484E691687A2816F48F5A103961D63D1456448904305F20EB664D69159A", Utc(2011, 12, 26), Utc(2023, 6, 21), Utc(2012, 3, 23)),
        new("2.16.76.1.7.1.5.2.1", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_1.der", Sha256, "724A857F9719DA83A16FF1C599EC59EF8AB1528CF2D54831F476E1A93A6DD3FF", Utc(2012, 3, 7), Utc(2023, 6, 21), Utc(2012, 9, 21)),
        new("2.16.76.1.7.1.5.1.2", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v1_2.der", Sha1, "EF4273928B6314E2C4E7319B26FDF0EFFAFE57A0", Utc(2012, 9, 21), Utc(2015, 1, 1), null),
        new("2.16.76.1.7.1.5.2.2", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_2.der", Sha256, "907AB12086955F7201DD5DC9636E6D11800F08FB7FCD1E64DB7EDD0A1E6B1BA9", Utc(2012, 9, 21), Utc(2023, 6, 21), Utc(2017, 2, 26)),
        new("2.16.76.1.7.1.1.2.2", "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_2.der", Sha256, "0F6FA2C6281981716C95C79899039844523B1C61C2C962289CDAC7811FEEE29E", Utc(2016, 4, 27), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.2.2.2", "http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_2.der", Sha256, "2FC28C6155A0574558D92C674D47158CDADB1144EAAEAFDA1CD76DBA967A6774", Utc(2016, 4, 27), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.4.2.2", "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_2.der", Sha256, "93DDE2288C02C4D7B674402871B4328272D4BBC791DBFFB5BD6061D812CFE609", Utc(2016, 4, 27), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.3.2.2", "http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_2.der", Sha256, "FF2727CEA8785691C60676CE240C7BF79E1586B3751D2D30CBE13601B796C69B", Utc(2016, 4, 27), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.5.2.3", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_3.der", Sha256, "3A339C7EC1D47EAC0D04B4D06377D4FD5B417B367E57890C3E890475922F2669", Utc(2016, 4, 27), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.1.2.3", "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_3.der", Sha256, "B16E88BBF77322A67995B79078778ED3D0EA7C88587B6F6D518B715E8F76A3D5", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.2.2.3", "http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_3.der", Sha256, "80DFE81E2A8AE762CD360253722922332EE10164D992156D847C47C8FB879CD2", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.3.2.3", "http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_3.der", Sha256, "08AB9799A528E211478EF5003E4CEC9C337CA82838DE1D6A7372C8789934AD4B", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.4.2.3", "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_3.der", Sha256, "2106EA59CCC2D314E5B7F1C75506A03F3B90BD5EB636B48075D6B60E7489BF18", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.5.2.4", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_4.der", Sha256, "E21A476B65EB647AD4056B7DE3D3513A8B14F6A8DE676D681FA362066EB0B628", Utc(2018, 5, 14), Utc(2029, 3, 2), null),
        new("2.16.76.1.7.1.1.2.4", "http://politicas.icpbrasil.gov.br/PA_AD_RB_v2_4.der", Sha256, "1F3C904C44C392FEEF447E21FAA7A04E85D9C0153346320F557B7042AF5DCF13", Utc(2025, 6, 12), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.2.2.4", "http://politicas.icpbrasil.gov.br/PA_AD_RT_v2_4.der", Sha256, "FA59DCA6D9C0E808EB7397B2DE800CCE5B0E4DA2C42E2E5EF2496A2CE6BADCB7", Utc(2025, 6, 12), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.3.2.4", "http://politicas.icpbrasil.gov.br/PA_AD_RV_v2_4.der", Sha256, "AC8D3299189A58F88EC938D1B5918F65BD9D1B22E1D1A32B998F3FDF07EC3342", Utc(2025, 6, 12), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.4.2.4", "http://politicas.icpbrasil.gov.br/PA_AD_RC_v2_4.der", Sha256, "AB0DD337580F7CCD6244E30F2A29F2E97614AD411838A0A1179D479504F5522B", Utc(2025, 6, 12), Utc(2037, 10, 22), null),
        new("2.16.76.1.7.1.5.2.5", "http://politicas.icpbrasil.gov.br/PA_AD_RA_v2_5.der", Sha256, "0531EE338ACB53364C8B316A11D90423EE33E714CB365D9C4562B90FA47D9099", Utc(2025, 6, 12), Utc(2037, 10, 22), null),
    ];

    private static DateTimeOffset Utc(int year, int month, int day) => new(year, month, day, 0, 0, 0, TimeSpan.Zero);
}
