namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddApiGatewayLogs : DbMigration
    {
        public override void Up()
        {
            CreateTable(
                "dbo.ApiGatewayLogs",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        IpAddress = c.String(maxLength: 50),
                        SessionId = c.String(maxLength: 128),
                        Username = c.String(maxLength: 256),
                        Controller = c.String(maxLength: 100),
                        ActionName = c.String(maxLength: 100),
                        RawUrl = c.String(maxLength: 500),
                        HttpMethod = c.String(maxLength: 20),
                        UserAgent = c.String(maxLength: 500),
                        IsAbnormal = c.Boolean(nullable: false),
                        RiskScore = c.Double(nullable: false),
                        AttackScore = c.Double(nullable: false),
                        PredictedLabel = c.String(maxLength: 50),
                        RuleAttack = c.Boolean(nullable: false),
                        FinalAction = c.String(maxLength: 50),
                        DecisionSource = c.String(maxLength: 100),
                        InterApiAccessDuration = c.Double(nullable: false),
                        ApiAccessUniqueness = c.Double(nullable: false),
                        SequenceLength = c.Double(nullable: false),
                        VsessionDuration = c.Double(nullable: false),
                        NumSessions = c.Double(nullable: false),
                        NumUsers = c.Double(nullable: false),
                        NumUniqueApis = c.Double(nullable: false),
                        RequestRatePerMin = c.Double(nullable: false),
                        GraphNumNodes = c.Double(nullable: false),
                        GraphNumEdges = c.Double(nullable: false),
                        GraphDensity = c.Double(nullable: false),
                        GraphSelfLoops = c.Double(nullable: false),
                        GraphAvgDegree = c.Double(nullable: false),
                        CreatedAt = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
        }
        
        public override void Down()
        {
            DropTable("dbo.ApiGatewayLogs");
        }
    }
}
