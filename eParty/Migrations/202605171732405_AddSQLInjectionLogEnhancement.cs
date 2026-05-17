namespace eParty.Migrations
{
    using System;
    using System.Data.Entity.Migrations;
    
    public partial class AddSQLInjectionLogEnhancement : DbMigration
    {
        public override void Up()
        {
            AddColumn("dbo.SQLInjectionLog", "Probability", c => c.Double());
            AddColumn("dbo.SQLInjectionLog", "DetectedBy", c => c.String());
            AddColumn("dbo.SQLInjectionLog", "RequestMethod", c => c.String());
            AddColumn("dbo.SQLInjectionLog", "UserId", c => c.String());
        }
        
        public override void Down()
        {
            DropColumn("dbo.SQLInjectionLog", "UserId");
            DropColumn("dbo.SQLInjectionLog", "RequestMethod");
            DropColumn("dbo.SQLInjectionLog", "DetectedBy");
            DropColumn("dbo.SQLInjectionLog", "Probability");
        }
    }
}
