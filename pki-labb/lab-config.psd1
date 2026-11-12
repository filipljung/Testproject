@{
    # Domän och namnrymd. .internal är reserverat av ICANN (2024) för privata nätverk
    # och kan aldrig krocka med en publik domän.
    DomainName   = 'testby.internal'
    NetBIOS      = 'TESTBY'
    OrgOU        = 'Testby'

    # PKI
    PkiHost      = 'pki.testby.internal'          # DNS-alias för CDP/AIA (pekar på SUBCA01)
    RootCAName   = 'Testby-Root-CA'
    SubCAName    = 'Testby-Issuing-CA-01'
    CADNSuffix   = 'O=Testby kommun,C=SE'

    # Nätverk (Hyper-V-switchen LabNet med NAT, se docs/02-bygginstruktion.md)
    PrefixLength = 24
    Gateway      = '10.10.10.1'

    DC     = @{ Name = 'DC01';    IP = '10.10.10.10' }
    RootCA = @{ Name = 'ROOTCA';  IP = '10.10.10.20' }
    SubCA  = @{ Name = 'SUBCA01'; IP = '10.10.10.30' }

    # Testkonton som skapas av 01-DC01-Install.ps1
    TestUsers = @(
        @{ Sam = 'anna.andersson'; GivenName = 'Anna'; Surname = 'Andersson'; OU = 'Anstallda' }
        @{ Sam = 'bo.berg';        GivenName = 'Bo';   Surname = 'Berg';      OU = 'Anstallda' }
        @{ Sam = 'elsa.elev';      GivenName = 'Elsa'; Surname = 'Elev';      OU = 'Elever'    }
        @{ Sam = 'kalle.konsult';  GivenName = 'Kalle'; Surname = 'Konsult';  OU = 'Konsulter' }
    )
}
