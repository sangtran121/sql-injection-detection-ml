namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class resethard : DbMigration
    {
        public override void Up()
        {
            DropTable("dbo.ApiGatewayLog");
            DropTable("dbo.BlockedIp");
        }
        
        public override void Down()
        {
            CreateTable(
                "dbo.BlockedIp",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        IpAddress = c.String(),
                        Reason = c.String(),
                        BlockedAt = c.DateTime(nullable: false),
                        ExpiredAt = c.DateTime(),
                        IsActive = c.Boolean(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
            CreateTable(
                "dbo.ApiGatewayLog",
                c => new
                    {
                        Id = c.Int(nullable: false, identity: true),
                        IpAddress = c.String(maxLength: 100),
                        SessionId = c.String(maxLength: 100),
                        ControllerName = c.String(maxLength: 100),
                        ActionName = c.String(maxLength: 100),
                        RiskScore = c.Double(nullable: false),
                        MlAction = c.String(maxLength: 50),
                        PredictedLabel = c.String(maxLength: 20),
                        RequestCount = c.Int(nullable: false),
                        CreatedDate = c.DateTime(nullable: false),
                    })
                .PrimaryKey(t => t.Id);
            
        }
    }
}
