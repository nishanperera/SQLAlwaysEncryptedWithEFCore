using Microsoft.EntityFrameworkCore;

namespace WebAppWithEFCore
{
    public partial class WebAppDbContext : DbContext
    {
        public WebAppDbContext()
        {
        }

        public WebAppDbContext(DbContextOptions<WebAppDbContext> options)
            : base(options)
        {
        }

        public virtual DbSet<AkvTestTable> AkvTestTable { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<AkvTestTable>(entity =>
            {
                entity.HasNoKey();

                entity.ToTable("AKV_TEST_TABLE");

                entity.Property(e => e.FirstName).HasMaxLength(50);

                entity.Property(e => e.LastName).HasMaxLength(50);
            });

        }
    }
}
